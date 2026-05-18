import os
import shutil
import stat
import sys
import textwrap
from pathlib import Path

import sdk
from ann import RuntimeEnv, RuntimeKey


def _file_mode():
    return stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH


def _config_mode():
    return stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH


def _make_shell_func(func_name: str, cli_file: str, exit_code: int) -> str:
    return textwrap.dedent(f'''
        {func_name}() {{
            result=$({cli_file} "{func_name}" "$@")

            if [ $? -eq {exit_code} ]; then
                eval "$result"
            elif [ -n "$result" ]; then
                # shellcheck disable=SC2039
                echo -e "$result"
            fi
        }}
    ''')


def copy_lib_files(source_dir: Path, runtime_dir: Path):
    """Phase 1: Copy pybin library files to ~/.pybin/pybinlib/."""
    shutil.rmtree(runtime_dir, ignore_errors=True)
    runtime_dir.mkdir(parents=True)

    pkg_dir = runtime_dir / "pybinlib"
    pkg_dir.mkdir()
    for name in ["sdk.py", "ann.py", "cli.py", "__about__.py", "__init__.py"]:
        shutil.copy(source_dir / name, pkg_dir)

    # Ensure cli.py has the correct shebang
    cli_path = pkg_dir / "cli.py"
    content = cli_path.read_text()
    if content.startswith("#!/"):
        cli_path.write_text(f"#!{sys.executable}\n" + content.split("\n", 1)[1])

    # Merge built-in config with user config
    config = sdk.read_json_file(str(source_dir / "config.json"))
    user_config_file = sdk.get_home() / ".pybin_config.json"
    if user_config_file.exists():
        sdk.merge_two_levels_dict(config, sdk.read_json_file(str(user_config_file)))
    sdk.write_json_file(str(runtime_dir / "config.json"), config)

    for name in ["sdk.py", "ann.py", "cli.py", "__about__.py", "__init__.py"]:
        os.chmod(pkg_dir / name, _file_mode())
    os.chmod(runtime_dir / "config.json", _config_mode())


def install_commands(cli_path: Path, runtime_dir: Path, shell_lines: list, installed_clis: list):
    """Install commands from a cli.py: symlinks for PYTHON, shell functions for SHELL.

    For built-ins, cli_path is runtime_dir/cli.py (symlinks point there).
    For extensions, cli_path is the original extension path (symlinks point there directly).
    """
    funcs_map = sdk.get_module_funcs_by_ast(str(cli_path))

    for name, func in funcs_map.get(RuntimeEnv.PYTHON.value, {}).items():
        symlink = runtime_dir / name
        if symlink.exists() or symlink.is_symlink():
            symlink.unlink()
        os.symlink(cli_path, symlink)

    for name, func in funcs_map.get(RuntimeEnv.SHELL.value, {}).items():
        exit_code = getattr(func, RuntimeKey.EXIT_CODE.value, 0)
        shell_lines.append(_make_shell_func(name, str(cli_path), exit_code))

    if funcs_map:
        installed_clis.append(str(cli_path))


def install_extensions(runtime_dir: Path, shell_lines: list, installed_clis: list):
    """Phase 3: Install extension commands from extend_clis.

    Extensions are symlinked to their original cli.py path so the extension's
    own shebang determines which Python/venv is used.
    """
    config = sdk.read_json_file(str(runtime_dir / "config.json"))
    for ext_path in config.get("pybin", {}).get("extend_clis", []):
        ext = Path(ext_path)
        if not ext.exists():
            print(f"Warning: extension not found: {ext_path}, skipping.")
            continue
        install_commands(ext, runtime_dir, shell_lines, installed_clis)


def generate_profile(runtime_dir: Path, source_dir: Path, installed_clis: list, shell_lines: list):
    """Phase 4: Write pybin_profile (rc aliases, cli.sh source, PATH, env vars)."""
    # cli.sh
    shell = "#!/usr/bin/env sh\n" + "".join(shell_lines)
    sdk.write_file_content(str(runtime_dir / "cli.sh"), shell)
    os.chmod(runtime_dir / "cli.sh", _file_mode())
    
    config = sdk.read_json_file(str(runtime_dir / "config.json"))
    pybin_cfg = config.get("pybin", {})
    rcs = dict(pybin_cfg.get("default_rc", {}))
    sdk.merge_two_levels_dict(rcs, pybin_cfg.get("rc", {}))
    for name in pybin_cfg.get("disable_rc", []):
        rcs.pop(name, None)

    clis = ";".join(installed_clis)
    lines = [line + "\n" for line in rcs.values()]
    lines.append(f"source {runtime_dir / 'cli.sh'}\n")
    lines.append(f'export PATH="{runtime_dir}:$PATH"\n')
    lines.append(f'export PYTHONPATH="{runtime_dir}:$PYTHONPATH"\n')
    lines.append(f'export PYBIN_CLIS="{clis}"\n')
    lines.append(f'export PYBIN_RUNTIME_PATH="{runtime_dir}"\n')
    lines.append(f'export PYBIN_SOURCE_PATH="{source_dir}"\n')
    sdk.write_file(str(runtime_dir / "pybin_profile"), lines)


def register_shell_startup(runtime_dir: Path):
    """Phase 5: Add source line to shell profile (.zshrc/.bashrc) if missing."""
    py_profile = str(runtime_dir / "pybin_profile")
    shell_configs = sdk.get_sh_profiles()
    primary = shell_configs[0]

    if py_profile not in open(primary).read():
        sdk.write_file_content_by_append(
            primary, f'\n[[ -s "{py_profile}" ]] && source "{py_profile}"\n'
        )


def install():
    source_dir = Path(__file__).resolve().parent
    runtime_dir = sdk.get_home() / ".pybin"

    # Phase 1
    copy_lib_files(source_dir, runtime_dir)

    shell_lines = []
    installed_clis = []

    # Phase 2
    install_commands(runtime_dir / "pybinlib" / "cli.py", runtime_dir, shell_lines, installed_clis)

    # Phase 3
    install_extensions(runtime_dir, shell_lines, installed_clis)

    # Phase 4
    generate_profile(runtime_dir, source_dir, installed_clis, shell_lines)

    # Phase 5
    register_shell_startup(runtime_dir)

    print("installed successfully.")


if __name__ == "__main__":
    install()
