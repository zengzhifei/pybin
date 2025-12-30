#!/usr/bin/env python3
import argparse
import os.path
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path


def pre_version_check():
    min_version = (3, 6, 0)
    if sys.version_info < min_version:
        print(f"python version required {'.'.join(map(str, min_version))} or later.")
        sys.exit(1)


def install_requirements(args):
    with open(os.devnull, "wb") as devnull:
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt',
                                   '--disable-pip-version-check'], stdout=devnull)

            import sdk
            other_config_file = sdk.get_home().joinpath(".pybin_config.json")
            if not other_config_file.exists():
                return
            other_config = sdk.read_json_file(str(other_config_file))
            for extend_cli in other_config.get('__extend_clis', []):
                if not Path(extend_cli).exists():
                    continue
                requirements = Path.absolute(Path(extend_cli)).parent.joinpath('requirements.txt')
                if not requirements.exists():
                    continue
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', requirements,
                                       '--disable-pip-version-check'], stdout=devnull)

        except subprocess.CalledProcessError:
            if not args.ignore_error:
                sys.exit(1)


def install_bin(args):
    import sdk
    from ann import RuntimeEnv, RuntimeKey

    root_path = sdk.get_home().joinpath(".pybin")
    current_path = Path.absolute(Path(__file__)).parent

    config = sdk.read_json_file(str(current_path.joinpath("config.json")))
    other_config_file = sdk.get_home().joinpath(".pybin_config.json")
    if other_config_file.exists():
        other_config = sdk.read_json_file(str(other_config_file))
    else:
        other_config = {}
    sdk.merge_two_levels_dict(config, other_config)

    if os.path.exists(root_path):
        shutil.rmtree(root_path)
    if not os.path.exists(root_path):
        os.mkdir(root_path)

    shutil.copy(current_path.joinpath("sdk.py"), root_path)
    shutil.copy(current_path.joinpath("ann.py"), root_path)
    shutil.copy(current_path.joinpath("cli.py"), root_path)
    shutil.copy(current_path.joinpath("__about__.py"), root_path)
    sdk.write_json_file(str(root_path.joinpath("config.json")), config)

    mode = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
    mode |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH

    os.chmod(root_path.joinpath("sdk.py"), mode=mode)
    os.chmod(root_path.joinpath("ann.py"), mode=mode)
    os.chmod(root_path.joinpath("cli.py"), mode=mode)
    os.chmod(current_path.joinpath("__about__.py"), mode=mode)
    os.chmod(root_path.joinpath("config.json"), mode=stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

    funcs_map = sdk.get_module_funcs('cli.py')
    python_funcs = funcs_map.get(RuntimeEnv.PYTHON.value, {})
    for name, func in python_funcs.items():
        os.symlink(root_path.joinpath("cli.py"), root_path.joinpath(name))

    shell_content = '''\
        #!/usr/bin/env sh
        '''
    template = '''
        {func_name}() {{
            result=$({cli_file} "{func_name}" "$@")

            if [ $? -eq {exit_code} ]; then
                eval "$result"
            elif [ -n "$result" ]; then
                # shellcheck disable=SC2039
                echo -e "$result"
            fi
        }}
        '''
    shell_funcs = funcs_map.get(RuntimeEnv.SHELL.value, {})
    for name, func in shell_funcs.items():
        shell_exit_code = getattr(func, RuntimeKey.EXIT_CODE.value, 0)
        shell_content += template.format(cli_file='cli.py', func_name=name, exit_code=shell_exit_code)

    installed_clis = str(root_path.joinpath("cli.py"))
    for extend_cli in config.get('__extend_clis', []):
        if not Path(extend_cli).exists():
            continue
        new_extend_cli = sdk.get_file_md5(extend_cli) + ".py"
        root_extend_cli = root_path.joinpath(new_extend_cli)
        shutil.copy(extend_cli, root_extend_cli)
        os.chmod(root_extend_cli, mode=mode)
        extend_funcs_map = sdk.get_module_funcs(root_extend_cli)
        extend_python_funcs = extend_funcs_map.get(RuntimeEnv.PYTHON.value, {})
        for extend_name, extend_func in extend_python_funcs.items():
            os.symlink(root_extend_cli, root_path.joinpath(extend_name))
        extend_shell_funcs = extend_funcs_map.get(RuntimeEnv.SHELL.value, {})
        for extend_name, extend_func in extend_shell_funcs.items():
            shell_exit_code = getattr(extend_func, RuntimeKey.EXIT_CODE.value, 0)
            shell_content += template.format(cli_file=new_extend_cli, func_name=extend_name, exit_code=shell_exit_code)
        installed_clis = installed_clis + ";" + str(root_extend_cli)

    sdk.write_file_content(str(root_path.joinpath("cli.sh")), textwrap.dedent(shell_content))
    os.chmod(root_path.joinpath("cli.sh"), mode=mode)

    py_rc = root_path.joinpath("pybinrc")
    rcs = config.get('pybin', {}).get('default_rc', {})
    sdk.merge_two_levels_dict(rcs, config.get('pybin', {}).get('rc', {}))
    if args.disable_rc is not None:
        for rc_name in list(set(args.disable_rc)):
            del rcs[rc_name]
    py_rc_config = [line + '\n' for line in rcs.values()]
    sdk.write_file(str(py_rc), py_rc_config)

    py_profile = root_path.joinpath("pybin_profile")
    py_config = [
        f'source {root_path.joinpath("pybinrc")}',
        f'source {root_path.joinpath("cli.sh")}',
        f'export PATH="{root_path}:$PATH"',
        f'export PYBIN_CLIS="{installed_clis}"',
        f'export PYBIN_RUNTIME_PATH="{root_path}"',
        f'export PYBIN_SOURCE_PATH="{current_path}"'
    ]
    py_config = [line + '\n' for line in py_config]
    sdk.write_file(str(py_profile), py_config)

    config = sdk.get_sh_profiles()[0]
    if f"{py_profile}" not in open(config).read():
        sdk.write_file_content_by_append(config, f'\n[[ -s "{py_profile}" ]] && source "{py_profile}"\n')


def install_site_packages(args):
    with open(os.devnull, "wb") as devnull:
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', '.'], stdout=devnull)
        except subprocess.CalledProcessError:
            if not args.ignore_error:
                sys.exit(1)


def install():
    parser = argparse.ArgumentParser(description="pybin installation program, you can define additional "
                                                 "configuration file: $HOME/.pybin_config.json")
    parser.add_argument("--disable-rc", type=str, nargs="+", help="disable rc config")
    parser.add_argument("--ignore-error", action="store_true", help="ignore install requirements error")
    args = parser.parse_args()

    pre_version_check()
    install_requirements(args)
    install_bin(args)
    install_site_packages(args)
    print("installed successfully.")


if __name__ == "__main__":
    install()
