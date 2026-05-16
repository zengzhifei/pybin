#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_VERSION="$(cat "$SCRIPT_DIR/.python-version")"
PYTHON_DIR="$SCRIPT_DIR/.python"
VENV_DIR="$SCRIPT_DIR/.venv"
UV_DIR="$SCRIPT_DIR/.uv"

FORCE=false
INSTALL=true

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --force      Remove existing .python/ and .venv/, rebuild from scratch.
  --env-only   Only prepare .python/ and .venv/, skip installing pybin.
  --help       Show this message.
EOF
    exit 0
}

for arg in "$@"; do
    case $arg in
        --force)     FORCE=true ;;
        --env-only)  INSTALL=false ;;
        --help)      usage ;;
        *)           echo "Unknown option: $arg"; usage ;;
    esac
done

fix_paths() {
    local cfg="$VENV_DIR/pyvenv.cfg"
    local home="$PYTHON_DIR/bin"
    local executable="$PYTHON_DIR/bin/python3"
    if [ "$(uname -s)" = "Darwin" ]; then
        sed -i '' "s|^home = .*|home = $home|" "$cfg"
        sed -i '' "s|^executable = .*|executable = $executable|" "$cfg"
    else
        sed -i "s|^home = .*|home = $home|" "$cfg"
        sed -i "s|^executable = .*|executable = $executable|" "$cfg"
    fi
}

find_system_python() {
    local sys_python
    if command -v python3 &>/dev/null; then
        sys_python=$(command -v python3)
        if "$sys_python" -c "" 2>/dev/null; then
            echo "$sys_python"
            return 0
        fi
    fi
    return 1
}

# Returns 0 if $1 (a python binary) has version < bundled version.
python_is_smaller() {
    local python_bin="$1" bv_major bv_minor
    bv_major=$(echo "$PYTHON_VERSION" | cut -d. -f1)
    bv_minor=$(echo "$PYTHON_VERSION" | cut -d. -f2)
    "$python_bin" -c "import sys; sys.exit(0 if sys.version_info[:2] < ($bv_major, $bv_minor) else 1)" 2>/dev/null
}

check_ready() {
    if [ "$FORCE" = true ]; then
        rm -rf "$PYTHON_DIR" "$VENV_DIR"
        return 1
    fi

    # If system has a smaller python3, prefer rebuilding with it
    local sys_python
    if sys_python=$(find_system_python) && python_is_smaller "$sys_python"; then
        echo "System python3 ($sys_python) < bundled $PYTHON_VERSION, will rebuild..."
        return 1
    fi

    # Fix up a bundled-Python venv so it's portable (symlinks + pyvenv.cfg).
    # Then test if it actually works. Only rebuild if it's genuinely broken.
    if [ -L "$VENV_DIR/bin/python" ]; then
        case "$(readlink "$VENV_DIR/bin/python")" in
            *".python/bin/python3"*)
                # Replace any absolute/broken symlinks with relative ones
                for link in "$VENV_DIR"/bin/python*; do
                    [ -L "$link" ] || continue
                    rm -f "$link"
                    ln -sf "../../.python/bin/python3" "$link"
                done
                # Fix pyvenv.cfg (may have CI-runner paths from the build machine)
                fix_paths
                ;;
        esac
    fi

    if [ -x "$VENV_DIR/bin/python" ]; then
        if "$VENV_DIR/bin/python" -c "" 2>/dev/null; then
            return 0
        fi
        echo "Bundled Python not compatible with this system, rebuilding..."
        return 1
    fi

    return 1
}

ensure_uv() {
    if command -v uv &>/dev/null; then
        echo "uv"
        return 0
    fi

    local uv_bin="$UV_DIR/uv"
    if [ -x "$uv_bin" ]; then
        echo "$uv_bin"
        return 0
    fi

    echo "Downloading uv..." >&2
    if ! curl -LsSf --connect-timeout 10 --max-time 60 https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="$UV_DIR" INSTALLER_NO_MODIFY_PATH=1 sh >&2; then
        echo "Warning: Failed to download uv." >&2
        return 1
    fi
    echo "$uv_bin"
    return 0
}

setup_python() {
    local uv_cmd="$1"

    echo "Installing Python $PYTHON_VERSION..."
    $uv_cmd python install "$PYTHON_VERSION"

    # Use uv python dir to find the managed Python installation (not a venv).
    # Must filter by platform — uv may cache multiple platforms locally.
    local uv_python_dir python_home platform
    uv_python_dir=$($uv_cmd python dir)
    case "$(uname -s)" in
        Darwin) platform="macos" ;;
        Linux)  platform="linux" ;;
    esac
    python_home=$(ls -d "$uv_python_dir/cpython-${PYTHON_VERSION}-${platform}-"* 2>/dev/null | head -1)

    if [ -z "$python_home" ]; then
        echo "Error: Could not find managed Python $PYTHON_VERSION for $platform in $uv_python_dir" >&2
        exit 1
    fi

    rm -rf "$PYTHON_DIR"
    mkdir -p "$PYTHON_DIR"
    echo "Copying Python to $PYTHON_DIR..."
    cp -R "$python_home"/. "$PYTHON_DIR/"
}

select_python() {
    local bundled_python="$PYTHON_DIR/bin/python3"

    # In CI/prep mode, always use bundled Python for portable tarballs
    if [ "${PYBIN_BUNDLED_ONLY:-}" = "1" ]; then
        echo "PYBIN_BUNDLED_ONLY=1, using bundled Python" >&2
        echo "$bundled_python"
        return
    fi

    local sys_python
    sys_python=$(find_system_python) || true

    if [ -n "$sys_python" ] && python_is_smaller "$sys_python"; then
        echo "System python3 ($("$sys_python" --version 2>&1)) < bundled ($PYTHON_VERSION)" >&2
        echo "-> Using system Python" >&2
        echo "$sys_python"
        return
    fi

    if [ -z "$sys_python" ]; then
        echo "No system python3, using bundled Python $PYTHON_VERSION" >&2
    else
        echo "System python3 ($("$sys_python" --version 2>&1)) >= bundled ($PYTHON_VERSION)" >&2
        echo "-> Using bundled Python" >&2
    fi
    echo "$bundled_python"
}

create_venv() {
    local uv_cmd="$1"
    local python_path="$2"

    echo "Creating virtual environment with $python_path..."
    rm -rf "$VENV_DIR"
    $uv_cmd venv "$VENV_DIR" --seed --python "$python_path"

    echo "Reinstalling pip..."
    rm -rf "$VENV_DIR"/lib/python*/site-packages/pip*
    $uv_cmd pip install --python "$VENV_DIR/bin/python" pip setuptools wheel

    # If we used the bundled Python, replace uv's absolute symlinks with
    # relative ones and fix pyvenv.cfg. This makes the tarball portable —
    # without it, the venv would hardcode the CI runner's paths.
    # Skip for system Python — its venv paths are already correct.
    case "$python_path" in
        "$PYTHON_DIR"/*)
            for link in "$VENV_DIR"/bin/python*; do
                [ -L "$link" ] || continue
                rm -f "$link"
                ln -sf "../../.python/bin/python3" "$link"
            done
            fix_paths
            ;;
    esac
}

# Fallback venv creation using stdlib (no uv required)
create_venv_fallback() {
    local python_path="$1"

    echo "Creating virtual environment with $python_path (stdlib venv)..."
    rm -rf "$VENV_DIR"
    "$python_path" -m venv --without-pip "$VENV_DIR"

    echo "Bootstrapping pip..."
    "$VENV_DIR/bin/python" -m ensurepip
    "$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel -q
}

install_deps() {
    local uv_cmd="$1"

    echo "Installing dependencies..."
    if [ -n "$uv_cmd" ]; then
        $uv_cmd pip install --python "$VENV_DIR/bin/python" -r "$SCRIPT_DIR/requirements.txt"
    else
        "$VENV_DIR/bin/python" -m pip install -r "$SCRIPT_DIR/requirements.txt" -q
    fi
}

main() {
    if [ "$(uname -s)" = "Darwin" ]; then
        xattr -r -d com.apple.quarantine "$SCRIPT_DIR" 2>/dev/null || true
    fi

    if ! check_ready; then
        local uv_cmd
        uv_cmd=$(ensure_uv) || true

        if [ -n "$uv_cmd" ]; then
            # Online: full flow with uv
            setup_python "$uv_cmd"
            local selected_python
            selected_python=$(select_python)
            create_venv "$uv_cmd" "$selected_python"
            install_deps "$uv_cmd"
        else
            # Offline: fallback to system Python
            local sys_python
            sys_python=$(find_system_python) || {
                echo "Error: No uv available and no system python3 found." >&2
                exit 1
            }
            echo "No uv available, using system Python: $sys_python"
            create_venv_fallback "$sys_python"
            install_deps ""
        fi
    fi

    if [ "$INSTALL" = true ]; then
        echo "Installing pybin..."
        "$VENV_DIR/bin/python" "$SCRIPT_DIR/pybin/install.py"
        echo "Run: source ~/.pybin/pybin_profile"
    fi
    echo "Done."
}

main
