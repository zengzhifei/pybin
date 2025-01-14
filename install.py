#!/usr/bin/env python3
import argparse
import os.path
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import sdk
from ann import RuntimeEnv
from cli import funcs as functions


def get_alias_config():
    return {
        'rm': 'alias rm="saferm"',
        's': 'alias s="scd"',
        'll': 'alias ll="ls -l"',
        'jsa': 'alias jsa="javaserver --status all"',
        'gt': 'alias gt="git status"'
    }


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
        except subprocess.CalledProcessError:
            if not args.ignore_error:
                sys.exit(1)


def install_config():
    if Path.absolute(Path(__file__)).parent.joinpath("config.json").exists():
        return 0

    try:
        subprocess.check_call([sys.executable, 'cli.py', 'securekeeper', '--type', 'dec', '--out',
                               'config.json', 'config.json.sec'])
    except subprocess.CalledProcessError:
        sys.exit(1)


def install_bin(args):
    root_path = sdk.get_home().joinpath(".pybin")
    current_path = Path.absolute(Path(__file__)).parent

    if os.path.exists(root_path):
        shutil.rmtree(root_path)
    if not os.path.exists(root_path):
        os.mkdir(root_path)

    shutil.copy(current_path.joinpath("sdk.py"), root_path)
    shutil.copy(current_path.joinpath("ann.py"), root_path)
    shutil.copy(current_path.joinpath("cli.py"), root_path)
    shutil.copy(current_path.joinpath("cli.sh"), root_path)
    shutil.copy(current_path.joinpath("__about__.py"), root_path)
    config = sdk.read_json_file(str(current_path.joinpath("config.json")))
    other_config_file = sdk.get_home().joinpath(".pybin_config.json")
    if other_config_file.exists():
        other_config = sdk.read_json_file(str(other_config_file))
    else:
        other_config = {}
    sdk.merge_two_levels_dict(config, other_config)
    sdk.write_json_file(str(root_path.joinpath("config.json")), config)

    mode = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
    mode |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH

    os.chmod(root_path.joinpath("sdk.py"), mode=mode)
    os.chmod(root_path.joinpath("ann.py"), mode=mode)
    os.chmod(root_path.joinpath("cli.py"), mode=mode)
    os.chmod(root_path.joinpath("cli.sh"), mode=mode)
    os.chmod(current_path.joinpath("__about__.py"), mode=mode)
    os.chmod(root_path.joinpath("config.json"), mode=stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

    funcs_map = functions()
    for env, funcs in funcs_map.items():
        if env == RuntimeEnv.PYTHON.value:
            for func in funcs:
                os.symlink(root_path.joinpath("cli.py"), root_path.joinpath(func))

    paths = os.getenv("PATH", "").split(":")
    config = sdk.get_sh_profiles()[0]

    py_profile = root_path.joinpath("pybin_profile")
    py_config = [
        f'source {root_path.joinpath("cli.sh")}',
        f'export PATH="{root_path}:$PATH"',
        f'export PYBIN_SOURCE_PATH="{current_path}"'
    ]

    alias_config = get_alias_config()
    if args.disable_alias is not None:
        if len(args.disable_alias) == 0:
            alias_config = {}
        else:
            for name in list(set(args.disable_alias)):
                del alias_config[name]

    py_config += list(alias_config.values())

    py_config = [line + '\n' for line in py_config]

    sdk.write_file(str(py_profile), py_config)

    if str(root_path) not in paths:
        with open(config, 'a', encoding="utf-8") as file:
            file.write(f'\nsource {py_profile}\n')


def install():
    alias_config = get_alias_config()

    parser = argparse.ArgumentParser(description="pybin installation program, you can define additional "
                                                 "configuration file: $HOME/.pybin_config.json")
    parser.add_argument("--disable-alias", choices=list(alias_config.keys()), nargs="*", help="disable choices alias")
    parser.add_argument("--ignore-error", action="store_true", help="ignore install requirements error")
    args = parser.parse_args()

    pre_version_check()
    install_requirements(args)
    install_config()
    install_bin(args)
    print("installed successfully.")


if __name__ == "__main__":
    install()
