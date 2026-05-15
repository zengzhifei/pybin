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
    local home="$PYTHON_DIR/bin"
    local executable="$PYTHON_DIR/bin/python3"
    local cfg="$VENV_DIR/pyvenv.cfg"
    if [ "$(uname -s)" = "Darwin" ]; then
        sed -i '' "s|^home = .*|home = $home|" "$cfg"
        sed -i '' "s|^executable = .*|executable = $executable|" "$cfg"
    else
        sed -i "s|^home = .*|home = $home|" "$cfg"
        sed -i "s|^executable = .*|executable = $executable|" "$cfg"
    fi
}

check_ready() {
    if [ "$FORCE" = true ]; then
        rm -rf "$PYTHON_DIR" "$VENV_DIR"
        return 1
    fi
    if [ -x "$PYTHON_DIR/bin/python3" ] && [ -x "$VENV_DIR/bin/python" ]; then
        fix_paths
        return 0
    fi
    return 1
}

ensure_uv() {
    if command -v uv &>/dev/null; then
        echo "uv"
        return
    fi

    local uv_bin="$UV_DIR/uv"
    if [ -x "$uv_bin" ]; then
        echo "$uv_bin"
        return
    fi

    echo "Downloading uv..." >&2
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="$UV_DIR" sh >&2
    echo "$uv_bin"
}

setup_python() {
    local uv_cmd="$1"

    echo "Installing Python $PYTHON_VERSION..."
    $uv_cmd python install "$PYTHON_VERSION"

    local python_bin
    python_bin=$($uv_cmd python find "$PYTHON_VERSION")
    local python_home
    python_home="$(dirname "$(dirname "$python_bin")")"

    rm -rf "$PYTHON_DIR"
    mkdir -p "$PYTHON_DIR"

    echo "Copying Python to $PYTHON_DIR..."
    cp -R "$python_home"/. "$PYTHON_DIR/"
}

create_venv() {
    local uv_cmd="$1"

    echo "Creating virtual environment..."
    rm -rf "$VENV_DIR"
    $uv_cmd venv "$VENV_DIR" --seed --python "$PYTHON_DIR/bin/python3"

    for link in "$VENV_DIR"/bin/python*; do
        [ -L "$link" ] || continue
        rm -f "$link"
        ln -sf "../../.python/bin/python3" "$link"
    done

    echo "Reinstalling pip..."
    rm -rf "$VENV_DIR"/lib/python*/site-packages/pip*
    $uv_cmd pip install --python "$VENV_DIR/bin/python" pip setuptools wheel

    fix_paths
}

install_deps() {
    local uv_cmd="$1"

    echo "Installing dependencies..."
    $uv_cmd pip install --python "$VENV_DIR/bin/python" -r "$SCRIPT_DIR/requirements.txt"
}

main() {
    if [ "$(uname -s)" = "Darwin" ]; then
        xattr -r -d com.apple.quarantine "$SCRIPT_DIR" 2>/dev/null || true
    fi

    if ! check_ready; then
        local uv_cmd
        uv_cmd=$(ensure_uv)

        setup_python "$uv_cmd"
        create_venv "$uv_cmd"
        install_deps "$uv_cmd"
    fi

    if [ "$INSTALL" = true ]; then
        echo "Installing pybin..."
        "$VENV_DIR/bin/python" "$SCRIPT_DIR/pybin/install.py"
    fi
    echo "Done."
}

main
