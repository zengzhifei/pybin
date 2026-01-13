#!/usr/bin/env python3

import argparse
import ast
import cgi
import html
import inspect
import io
import json
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import urllib
from datetime import datetime, timedelta
from decimal import Decimal
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler
from pathlib import Path
from typing import Optional, TextIO, cast
from urllib.parse import urlparse

import humanize
import pandas as pd
import psutil as psutil
import requests as requests
from inotify_simple import INotify, flags
from tabulate import tabulate

import sdk
from __about__ import __version__, __author__
from ann import RuntimeEnv, runtime, RuntimeKey, RuntimeMode


def pybin():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-v", "--version", action="store_true", help="show version")
    group.add_argument("-u", "--author", action="store_true", help="show author")
    group.add_argument("-f", "--function", action="store_true", help="show function")
    group.add_argument("-i", "--install", "--update", action="store_true", help="install or update pybin")
    group.add_argument("-c", "--config", type=str, nargs="+", help="show config")
    group.add_argument("-r", "--rc", action="store_true", help="show rc config")
    group.add_argument("--history", action="store_true", help="show cmd run history")
    args = parser.parse_args()

    if args.install:
        source_path = os.environ.get("PYBIN_SOURCE_PATH")
        os.chdir(source_path)
        process = sdk.run_shell(f"{sys.executable} install.py")
        print(process.stdout.rstrip('\n'))
        return

    if args.config:
        config_keys = args.config
        config: dict = sdk.get_config(config_keys[0], is_caller=False)
        for key in config_keys[1:]:
            config = config.get(key)
        if isinstance(config, dict):
            print(sdk.format_json(config))
        else:
            print(config)
        return

    if args.rc:
        rcs = sdk.get_config('default_rc', default_value={})
        sdk.merge_two_levels_dict(rcs, sdk.get_config('rc', default_value={}))
        py_rc = os.path.join(os.environ.get("PYBIN_RUNTIME_PATH"), "pybinrc")
        configured_rc = sdk.read_file(py_rc)

        rows = []
        for rc_name, rc_value in rcs.items():
            if rc_value + "\n" in configured_rc:
                rows.append(["installed", rc_name, rc_value])
            else:
                rows.append(["uninstalled", rc_name, rc_value])
        print(tabulate(rows, headers=["install status", "rc name", "rc value"], tablefmt="pretty"))
        return

    if args.history:
        print(sdk.read_file_content(os.path.join(sdk.get_home(), ".pybin_history")))
        return

    if not args.version and not args.author and not args.function:
        args.version = args.author = args.function = True

    headers = []
    rows = []
    if args.version:
        headers.append("version")
        rows.append(__version__)
    if args.author:
        headers.append("author")
        rows.append(__author__)
    if args.function:
        clis = os.environ.get("PYBIN_CLIS").split(";")
        for cli in clis:
            headers.append(f"{os.path.basename(cli)}")
            funcs = [k for functions in sdk.get_module_funcs(cli).values() for k, v in functions.items()]
            rows.append(tabulate([funcs[i:i + 3] for i in range(0, len(funcs), 3)], tablefmt="plain"))

    print(tabulate([rows], headers=headers, tablefmt="grid", rowalign=None))


@runtime(env=RuntimeEnv.SHELL, shell_exit_code=250)
def sourcerc():
    profiles = sdk.get_sh_profiles()
    source_files = []
    for profile in profiles:
        if not os.path.exists(profile):
            continue
        else:
            source_files.append(f"source {profile}")

    py_profile = sdk.get_home().joinpath(".pybin").joinpath("pybin_profile")
    source_files.append(f"source {py_profile}")
    cmd = "; ".join(source_files)
    print(cmd)
    sys.exit(250)


@runtime(env=RuntimeEnv.SHELL, shell_exit_code=250)
def scd():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--list", type=int, help="less or equal 0 is list all")
    parser.add_argument("-q", "--query", type=str)
    parser.add_argument("-c", "--config", type=int, nargs=2)
    parser.add_argument("-d", "--delete", type=int)
    parser.add_argument("dir", type=str, nargs="?")
    args = parser.parse_args()

    data_file = sdk.get_home().joinpath(".scd")
    if not os.path.exists(data_file):
        file = open(data_file, 'w')
        file.close()

    if args.list is not None:
        line_count = None if args.list <= 0 else args.list
        print("".join(sdk.read_file(str(data_file), line_count=line_count, line_num=True)))
        return

    if args.query is not None:
        contents = sdk.read_file(str(data_file), line_num=True)
        for content in contents:
            if args.query.lower() in content.lower():
                print(content, end="")
        return

    if args.config is not None:
        update_id = args.config[0] - 1
        update_count = args.config[1]
        contents = sdk.read_file(str(data_file))
        cols = contents[update_id].split("|")
        cols[1] = str(update_count)
        contents[update_id] = "|".join(cols)
        sdk.write_file(str(data_file), contents)
        return

    if args.delete is not None:
        contents = sdk.read_file(str(data_file))
        if len(contents) >= args.delete:
            del contents[args.delete - 1]
            sdk.write_file(str(data_file), contents)
        return

    target_dir = "." if args.dir is None else args.dir
    target_dir = os.path.abspath(target_dir)
    exists_dir = os.path.exists(target_dir)
    dir_basename = os.path.basename(target_dir)

    dir_item = {}
    contents = sdk.read_file(str(data_file))
    for content in contents:
        cols = content.split("|")
        item = {'dir_count': int(cols[1]), 'dir_time': int(cols[2])}
        dir_item[cols[0]] = item

    if not exists_dir:
        filtered_data = {k: v for k, v in dir_item.items() if dir_basename.lower() in k.lower()}
        if len(filtered_data) == 0:
            return
        target_dir, target_item = max(filtered_data.items(), key=lambda x: (x[0].lower().endswith(dir_basename.lower()),
                                                                            x[1]['dir_count'],
                                                                            x[1]['dir_time'])
                                      )

    if target_dir in dir_item:
        item = {'dir_count': dir_item[target_dir]['dir_count'] + 1, 'dir_time': int(time.time())}
        dir_item[target_dir] = item
    else:
        item = {'dir_count': 1, 'dir_time': int(time.time())}
        dir_item[target_dir] = item

    new_dir_item = sorted(dir_item.items(), key=lambda it: (it[1]['dir_count'], it[1]['dir_time']), reverse=True)
    new_contents = []
    for new_dir, new_value in new_dir_item:
        new_contents.append(f"{new_dir}|{new_value['dir_count']}|{new_value['dir_time']}\n")
    sdk.write_file(str(data_file), new_contents)

    print(f"cd {target_dir}")

    sys.exit(250)


@runtime(env=RuntimeEnv.SHELL, shell_exit_code=250)
def java_decompiler():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cfr', type=str, required=True, help="download from https://www.benf.org/other/cfr/")
    parser.add_argument('class_file', type=str)
    args = parser.parse_args()

    cmd = f"java -jar {args.cfr} {args.class_file}"
    print(cmd)

    sys.exit(250)


@runtime(env=RuntimeEnv.SHELL, shell_exit_code=250)
def gomysql():
    parser = argparse.ArgumentParser()
    parser.add_argument("tag", choices=list(cast(dict, sdk.get_config(key=None)).keys()))
    parser.add_argument("cmds", type=str, nargs="*")
    args = parser.parse_args()

    config = sdk.get_config(args.tag)

    if args.cmds is None:
        cmd = f'mysql -A {config} --default-character-set=utf8'
    else:
        cmd = f'mysql -A {config} --default-character-set=utf8 {" ".join(shlex.quote(cmd) for cmd in args.cmds)}'

    print(cmd)

    sys.exit(250)


@runtime(env=RuntimeEnv.SHELL, shell_exit_code=250)
def goredis():
    parser = argparse.ArgumentParser()
    parser.add_argument("tag", choices=list(cast(dict, sdk.get_config(key=None)).keys()))
    parser.add_argument("cmds", type=str, nargs="*")
    args = parser.parse_args()

    config = sdk.get_config(args.tag)

    if "-h " in config:
        conn = config
    else:
        service_info = sdk.parse_bns(config)
        info = service_info[0]
        ip = info['ip']
        port = int(info['port'])
        conn = f"-h {ip} -p {port}"

    # can use --no-auth-warning in config
    if args.cmds is None:
        cmd = f'redis-cli {conn} --raw'
    else:
        cmd = f'redis-cli {conn} --raw {" ".join(shlex.quote(cmd) for cmd in args.cmds)}'

    print(cmd)

    sys.exit(250)


@runtime(env=RuntimeEnv.SHELL, shell_exit_code=250)
def gomachine():
    parser = argparse.ArgumentParser()
    parser.add_argument("machine", type=str)
    args = parser.parse_args()

    config: dict = sdk.get_config(args.machine)
    host = config.get('host')
    passwd = config.get('passwd')
    if passwd is not None and passwd:
        cmd = f"sshpass -p {passwd} ssh {host}"
    else:
        cmd = f"ssh {host}"

    print(cmd)

    sys.exit(250)


@runtime(env=RuntimeEnv.SHELL, shell_exit_code=250)
def goinstance():
    parser = argparse.ArgumentParser()
    parser.add_argument("instance", type=str)
    args = parser.parse_args()

    try:
        instance = sdk.get_config(args.instance)
    except KeyError:
        instance = args.instance

    cmd = f"ssh --matrix {instance}"
    print(cmd)

    sys.exit(250)


@runtime(env=RuntimeEnv.SHELL, shell_exit_code=250)
def pydebug():
    parser = argparse.ArgumentParser()
    parser.add_argument("cmds", type=str, nargs="+")
    args = parser.parse_args()

    run_mode = os.getenv(RuntimeKey.MODE.value)
    cmds = [
        f'export {RuntimeKey.MODE.value}={RuntimeMode.DEBUG.value}',
        f'{" ".join(shlex.quote(cmd) for cmd in args.cmds)}',
        f'export {RuntimeKey.MODE.value}={run_mode}',
    ]

    print("\n".join(cmds))

    sys.exit(250)


@runtime(env=RuntimeEnv.SHELL, shell_exit_code=250)
def deep_find_app():
    parser = argparse.ArgumentParser()
    parser.add_argument('app', type=str)
    args = parser.parse_args()

    cmd = f'find ~/Library -type d -iname "*{args.app}*" 2>/dev/null | sed "s/ /\\ /g"'
    print(cmd)
    sys.exit(250)


def goes():
    parser = argparse.ArgumentParser()
    parser.add_argument('--raw', action='store_true')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument("tag", choices=list(cast(dict, sdk.get_config(key=None)).keys()))
    parser.add_argument('sql', type=str, nargs="?")
    args = parser.parse_args()

    def __print_verbose(*infos: str):
        if args.verbose is False:
            return
        print(sdk.beautify_separator_line())
        for info in infos:
            print(info)
        print(sdk.beautify_separator_line())

    if args.sql is None:
        sql = sdk.get_multiline_input('enter sql and press enter twice to end:')
        print(sdk.beautify_separator_line())
    else:
        sql = args.sql

    ip_host = sdk.get_config(args.tag)

    match_show_tables = re.match(r'^\s*show\s+tables\s*$', sdk.trim(sql).rstrip(';'), re.IGNORECASE)
    match_show_table_ddl = re.match(r'^\s*show\s+create\s+table\s+(.+)\s*$', sdk.trim(sql).rstrip(';'), re.IGNORECASE)
    if match_show_tables:
        url = f'http://{ip_host}/_cat/indices?v'
        __print_verbose(url)
        response = requests.get(url)
    elif match_show_table_ddl:
        table = match_show_table_ddl.group(1)
        url = f'http://{ip_host}/{table}/_mapping'
        __print_verbose(url)
        response = requests.get(url)
    else:
        converter = sdk.Sql2EsConverter(sql).convert()
        index = converter.get_index()
        dsl = converter.get_dsl()
        url = f'http://{ip_host}/{index}/_search'
        __print_verbose(url, dsl)
        response = requests.post(url, json=json.loads(dsl))

    content_type = response.headers.get('Content-Type', 'text/plain; charset=UTF-8')
    if 'application/json' in content_type:
        if args.raw:
            print(response.json())
        else:
            print(json.dumps(response.json(), indent=2))
    else:
        print(response.text)


def sql2es():
    parser = argparse.ArgumentParser()
    parser.add_argument('sql', type=str, nargs='?')
    args = parser.parse_args()

    if args.sql is None:
        sql = sdk.get_multiline_input('enter sql and press enter twice to end:')
        print(sdk.beautify_separator_line())
    else:
        sql = args.sql

    converter = sdk.Sql2EsConverter(sql).convert()
    print(converter.get_dsl())


def dusort():
    parser = argparse.ArgumentParser()
    parser.add_argument('--depth', type=int, default=1)
    args = parser.parse_args()

    cmd = f'(du -h --max-depth={args.depth} . 2>/dev/null || du -h -d 1 .) | sort -rh'
    result = sdk.run_shell(cmd)
    print(result.stdout)


def hostpwd():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=str, nargs="?", default="")
    args = parser.parse_args()

    file = args.file
    user = os.getenv("USER")
    ip = sdk.get_ip()
    cwd = os.getcwd()
    print(f"{user}@{ip}:{cwd}/{file}")


def gpush():
    branch_cmd = f"git branch | grep '*' | awk '{{print $2}}'"
    result = sdk.run_shell(branch_cmd)
    branch: str = result.stdout
    branch = branch.strip()
    print(f"ready to push {branch}...")
    push_cmd = f"git push origin HEAD:refs/for/{branch}"
    result = sdk.run_shell(push_cmd)
    print(result.stderr)


def gitclear():
    cmd1 = "git remote prune origin"
    cmd2 = "git branch -a | grep -v '*' | awk '{if($1 ~ /remotes/){rbs[$1]=1} else {lbs[$1]=1}} END {for(rb in rbs){" \
           "print rb};for(lb in lbs){print lb}}' | awk '{if($1 ~ /remotes/){rbs[$1]=1}else if(rbs[" \
           "\"remotes/origin/\"$1] != 1){print $1}}' | xargs git branch -D"
    print(sdk.run_shell(cmd1).stderr)
    print(sdk.run_shell(cmd2).stdout)


def gitcp():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=str)
    parser.add_argument("--file", required=True, type=str)
    args = parser.parse_args()

    cmd = f"git checkout {args.source} -- {args.file}"
    sdk.run_shell(cmd)
    print(f"git copy {args.source} {args.file} success")


def gitrename():
    parser = argparse.ArgumentParser()
    parser.add_argument("--old_email", required=True, type=str)
    parser.add_argument("--new_name", required=True, type=str)
    parser.add_argument("--new_email", required=True, type=str)
    args = parser.parse_args()

    cmd = f"""
        git filter-branch -f --env-filter '
            OLD_EMAIL="'{args.old_email}'"
            CORRECT_NAME="'{args.new_name}'"
            CORRECT_EMAIL="'{args.new_email}'"
            if [ "$GIT_COMMITTER_EMAIL" = "$OLD_EMAIL" ]
            then
                export GIT_COMMITTER_NAME="$CORRECT_NAME"
                export GIT_COMMITTER_EMAIL="$CORRECT_EMAIL"
            fi
            if [ "$GIT_AUTHOR_EMAIL" = "$OLD_EMAIL" ]
            then
                export GIT_AUTHOR_NAME="$CORRECT_NAME"
                export GIT_AUTHOR_EMAIL="$CORRECT_EMAIL"
            fi
        ' HEAD
        """
    print(sdk.run_shell(cmd).stdout)


def gitfetch():
    parser = argparse.ArgumentParser()
    parser.add_argument("--temp-branch", "-t", required=False, type=str, default="temp")
    args = parser.parse_args()

    branch_cmd = f"git branch | grep '*' | awk '{{print $2}}'"
    result = sdk.run_shell(branch_cmd)
    branch: str = result.stdout
    branch = branch.strip()
    cmd = f"git branch {args.temp_branch} FETCH_HEAD && git checkout {branch} && git merge {args.temp_branch} "
    process = sdk.run_shell(cmd)
    print(process.stdout)
    cmd2 = f"git branch -D {args.temp_branch}"
    process2 = sdk.run_shell(cmd2)
    print(process2.stdout)


def saferm():
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()

    trash_dir = sdk.get_home().joinpath(".safe_trash")
    if not os.path.exists(trash_dir):
        os.mkdir(trash_dir)

    now = datetime.now().strftime("%Y%m%d#%H%M%S")
    for file in args.files:
        if not os.path.exists(file):
            print(f"{file} not exists")
            continue

        abspath = os.path.abspath(file)
        if abspath.startswith(os.path.abspath(trash_dir)):
            if os.path.isdir(abspath):
                shutil.rmtree(abspath)
            else:
                os.remove(abspath)
        else:
            trans_file = abspath.replace("/", "#")
            trans_file_path = f"{trash_dir}/{now}{trans_file}"
            if not os.path.exists(trans_file_path):
                os.mkdir(trans_file_path)
            shutil.move(abspath, trans_file_path)


def cleartrash():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ago", type=int, default=7, help="default 7 days ago")
    args = parser.parse_args()

    ago_time = datetime.now() - timedelta(days=args.ago)
    ago_day = ago_time.strftime("%Y%m%d")

    trash_dir = sdk.get_home().joinpath(".safe_trash")
    files = os.listdir(trash_dir)
    os.chdir(trash_dir)
    for file in files:
        day = file.split("#")[0]
        if day > ago_day:
            continue

        shutil.rmtree(file)
        print(f"{file} is removed.")


@runtime(env=RuntimeEnv.SHELL, shell_exit_code=250)
def runcmd():
    parser = argparse.ArgumentParser()
    parser.add_argument("name", choices=list(cast(dict, sdk.get_config(key=None)).keys()))
    parser.add_argument("params", type=str, nargs="*")
    args = parser.parse_args()

    templates = sdk.get_config(args.name)
    if isinstance(templates, str):
        templates = [templates]

    cmds = []
    for template in templates:
        placeholder_count = template.count('{}')
        if len(args.params) < placeholder_count:
            raise ValueError("Not enough values provided for the placeholders")

        formatted_string = template
        for _ in range(placeholder_count):
            formatted_string = formatted_string.replace('{}', str(args.params.pop(0)), 1)

        if not formatted_string.endswith(";"):
            formatted_string = f"{formatted_string};"

        cmds.append(formatted_string)

    cmd = " ".join(cmds)

    print(cmd)

    sys.exit(250)


def trim():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", type=int, choices=[0, 1, 2, 3, 4], required=False, default=0,
                        help="0 for all, 1 for head, 2 for button, 3 for left, 4 for right")
    parser.add_argument("text", type=str, nargs="?")
    args = parser.parse_args()

    if args.text is not None:
        text = args.text.replace('\\n', '\n')
    else:
        text = sys.stdin.read()

    print(sdk.trim(text, args.t))


def toupper():
    parser = argparse.ArgumentParser()
    parser.add_argument("text", type=str, nargs="?")
    args = parser.parse_args()

    if args.text is not None:
        text = args.text
    else:
        text = sys.stdin.read()

    print(text.upper())


def tolower():
    parser = argparse.ArgumentParser()
    parser.add_argument("text", type=str, nargs="?")
    args = parser.parse_args()

    if args.text is not None:
        text = args.text
    else:
        text = sys.stdin.read()

    print(text.lower())


def lgrep():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keyword", type=str, required=True)
    parser.add_argument("file", type=str)
    args = parser.parse_args()

    cmd = f"grep -rHn --include='{args.file}' '{args.keyword}' . | awk -F: '{{a[$1]++}} END{{for(f in a) print f \": \" a[f]}}'"
    process = sdk.run_shell(cmd)
    print(process.stdout)


def hi():
    parser = argparse.ArgumentParser()
    parser.add_argument("--link", type=str, nargs="*")
    parser.add_argument("--label", type=str, nargs="*")
    parser.add_argument("--image", type=str)
    parser.add_argument("--at", type=str, nargs="*")
    parser.add_argument("--at-all", action="store_true")
    parser.add_argument("text", type=str, nargs="?")
    args = parser.parse_args()

    if args.text is not None:
        text = args.text
    else:
        text = sys.stdin.read()

    url = sdk.get_config("url")
    header = {'toid': list(map(int, sdk.get_config("toid").split(",")))}
    body = []
    if text:
        body.append({'content': text, 'type': 'TEXT'})
    if args.link is not None:
        for i in range(0, len(args.link)):
            link = args.link[i]
            item = {'href': link, 'type': 'LINK'}
            if args.label is not None and len(args.label) > i:
                item['label'] = args.label[i]
            body.append(item)
    if args.image is not None:
        body.append({'content': args.image, 'type': 'IMAGE'})

    if len(body) == 0:
        parser.exit(1)

    if (args.at is not None) or (args.at_all is True):
        item = {'type': 'AT'}
        if args.at is not None:
            item['atuserids'] = args.at
        if args.at_all is True:
            item['atall'] = args.at_all
        body.append(item)

    data = json.dumps({'message': {'header': header, 'body': body}})
    headers = {'Content-Type': 'application/json'}
    response = requests.post(url, headers=headers, data=data, timeout=10)
    print(response.json())


def email_sender():
    parser = argparse.ArgumentParser()
    parser.add_argument('--subject', type=str, required=True)
    parser.add_argument('--to', type=str, required=True)
    parser.add_argument('body', type=str, nargs="?")
    args = parser.parse_args()

    if args.body is not None:
        body = args.body
    else:
        body = sys.stdin.read()

    smtp_server = sdk.get_config('smtp_server')
    smtp_port = sdk.get_config('smtp_port')
    smtp_user = sdk.get_config('smtp_user')
    smtp_password = sdk.get_config('smtp_password')
    from_name = sdk.get_config('smtp_name')

    if body:
        sdk.send_email(smtp_server=smtp_server, smtp_port=smtp_port, smtp_user=smtp_user,
                       smtp_password=smtp_password, from_name=from_name, subject=args.subject,
                       body=body, to_emails=args.to.strip().split(','))


def csum():
    total_sum = 0
    for line in sys.stdin:
        number = float(line.strip())
        total_sum += number

    print(total_sum)


def mod():
    parser = argparse.ArgumentParser()
    parser.add_argument('dividend', type=int)
    args = parser.parse_args()

    for line in sys.stdin:
        divisor = int(line.strip())
        print(divisor % args.dividend)


def hashcode():
    parser = argparse.ArgumentParser()
    parser.add_argument('text', type=str)
    args = parser.parse_args()

    h = 0
    for ch in args.text:
        h = (31 * h + ord(ch)) & 0xFFFFFFFF
    if h >= 0x80000000:
        h -= 0x100000000

    print(h)


def mabs():
    parser = argparse.ArgumentParser()
    parser.add_argument("number", type=sdk.ArgParseType.number, nargs="?")
    args = parser.parse_args()

    if args.number is not None:
        number = args.number
    else:
        number = ast.literal_eval(sys.stdin.read().strip())

    print(abs(number))


def repeatfill():
    parser = argparse.ArgumentParser()
    parser.add_argument("--placeholder", type=str, default="{}")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--end", type=int, required=True)
    parser.add_argument("text", type=str, nargs="?")
    args = parser.parse_args()

    if args.text is not None:
        text = args.text
    else:
        text = sys.stdin.read()

    for i in range(args.start, args.end):
        print(text.replace(args.placeholder, str(i)), end="")


def securekeeper():
    parser = argparse.ArgumentParser()
    parser.add_argument("--type", type=str, choices=["enc", "dec"], required=True)
    parser.add_argument("--pass", "--password", dest="password", type=str)
    parser.add_argument("--out", "--output", dest="output", type=str, required=True)
    parser.add_argument("input", type=str)
    args = parser.parse_args()

    if args.password is not None:
        password = args.password
    else:
        password = input("please enter your password: ")

    if not os.path.exists(args.input):
        raise FileNotFoundError(f"{args.input} not found")

    if args.type == "enc":
        with open(args.input, 'rb') as file:
            plaintext = file.read()
        enc_data = sdk.aes_encrypt(plaintext, password)
        with open(args.output, 'wb') as f:
            f.write(enc_data)
        return

    if args.type == "dec":
        with open(args.input, 'rb') as file:
            data = file.read()
        try:
            dec_data = sdk.aes_decrypt(data, password)
        except Exception:
            raise ValueError("password is wrong")
        with open(args.output, 'wb') as file:
            file.write(dec_data)
        return


def securehooker():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pass", "--password", dest="password", type=str)
    parser.add_argument("config", type=str)
    args = parser.parse_args()

    if not os.path.exists(".git"):
        raise RuntimeError("Please execute it in the git repository and directory")

    if args.password is not None:
        password = args.password
    else:
        password = input("please enter your password: ")

    mode = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
    mode |= stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
    mode |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH

    pre_commit = f"""
        #!/bin/sh
        
        securekeeper --type enc --pass {password} --out {args.config}.sec {args.config}
        git add {args.config}.sec
    """
    pre_commit_file = ".git/hooks/pre-commit"
    sdk.write_file(pre_commit_file, [inspect.cleandoc(pre_commit)])
    os.chmod(pre_commit_file, mode=mode)

    post_merge = f"""
        #!/bin/sh
    
        securekeeper --type dec --pass {password} --out {args.config} {args.config}.sec
        """
    post_merge_file = ".git/hooks/post-merge"
    sdk.write_file(post_merge_file, [inspect.cleandoc(post_merge)])
    os.chmod(post_merge_file, mode=mode)


def crc32gen():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=str)
    args = parser.parse_args()

    print(sdk.crc32(args.input))


def pkiller():
    parser = argparse.ArgumentParser()
    parser.add_argument("name", type=str)
    args = parser.parse_args()

    name = args.name.lower()

    def callback(process_name: str, proc: psutil.Process):
        confirm = input(f"confirm kill this process([{proc.pid}]{process_name})? [Y/N]\n")
        if confirm.upper() == "Y":
            proc.kill()
            proc.wait(timeout=1)

    sdk.iterate_process(condition=lambda proc_name: name in proc_name, callback=callback)


def goserver():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--restart", action="store_true", help="restart server")
    group.add_argument("--stop", action="store_true", help="stop server")
    group.add_argument("--status", action="store_true", help="show server status")
    group.add_argument("--config", action="store_true", help="show server config")
    group.add_argument("--reload", action="store_true", help="reload server")
    parser.add_argument("-P", "--debug", action="store_true", help="run server in debug mode")
    parser.add_argument("-l", "--log", action="store_true", help="extra log in goserver log")
    parser.add_argument("-d", "--daemon", action="store_true", help="run server in daemon")
    parser.add_argument("app", type=str, help="bin or go code source file or all")
    args = parser.parse_args()

    app: str = args.app

    if args.restart:
        if not os.path.exists(app):
            raise FileNotFoundError(f"{app} not found")
        if not (os.path.isfile(app) and os.access(app, os.X_OK)) and not (app.endswith(".go")):
            raise FileNotFoundError(f"{app} not an executable program or go source code file.")

        target_file = os.path.basename(app)
        if app.endswith(".go"):
            project_dir, bin_name = sdk.get_path_parent_by_level(app, 1)
            os.chdir(project_dir)
            bin_name = f"{bin_name}_launcher_goserver"
            build_cmd = f'mkdir -p bin && go build -gcflags "all=-N -l" -o ./bin/{bin_name} {target_file}'
            sdk.run_shell(build_cmd)
            run_cmd = f"./bin/{bin_name}"
        else:
            _, bin_dir = sdk.get_path_parent_by_level(app, 1)
            project_dir, bin_name = sdk.get_path_parent_by_level(app, 2)
            os.chdir(project_dir)
            run_cmd = f"./{bin_dir}/{target_file}"

        sdk.iterate_process(condition=lambda process_name: ('_launcher_goserver' in process_name)
                                                           and (bin_name.lower() in process_name),
                            callback=lambda process_name, proc: proc.kill())
        if args.debug:
            debug_port = sdk.find_available_port(8100, 8200)
            run_cmd = f"dlv --continue --listen=:{debug_port} --headless=true --api-version=2 --accept-multiclient exec {run_cmd}"

        if args.daemon:
            run_cmd = f"{run_cmd} >/dev/null 2>&1 &"
        sdk.run_shell(run_cmd)
        sdk.write_file_content(".goserver.runcmd", run_cmd)
        print(run_cmd)
        return

    if args.stop:
        if app.lower() == "all":
            sdk.iterate_process(condition=lambda process_name: ('launcher_goserver' in process_name),
                                callback=lambda process_name, proc: proc.kill())
        else:
            sdk.iterate_process(condition=lambda process_name: ('launcher_goserver' in process_name)
                                                               and (app.lower() in process_name),
                                callback=lambda process_name, proc: proc.kill())
        return

    if args.status:
        def print_server_info(process_name, proc: psutil.Process):
            ports = sdk.get_process_listen_ports(proc.pid)
            print(f"server({process_name}) run pid: {proc.pid}, run port: {ports}")

        if app.lower() == "all":
            sdk.iterate_process(condition=lambda process_name: ('launcher_goserver' in process_name),
                                callback=print_server_info)
        else:
            sdk.iterate_process(condition=lambda process_name: ('launcher_goserver' in process_name)
                                                               and (app.lower() in process_name),
                                callback=print_server_info)
        return

    if args.config:
        if app.lower() == "all":
            sdk.iterate_process(condition=lambda process_name: ('launcher_goserver' in process_name),
                                callback=lambda process_name, proc: print(process_name))
        else:
            sdk.iterate_process(condition=lambda process_name: ('launcher_goserver' in process_name)
                                                               and (app.lower() in process_name),
                                callback=lambda process_name, proc: print(process_name))
        return

    if args.reload:
        if not os.path.exists(app):
            raise FileNotFoundError(f"{app} not found")
        if not (os.path.isfile(app) and os.access(app, os.X_OK)):
            raise FileNotFoundError(f"{app} not an executable program.")

        project_dir, bin_name = sdk.get_path_parent_by_level(app, 2)
        os.chdir(project_dir)

        sdk.iterate_process(condition=lambda process_name: ('_launcher_goserver' in process_name)
                                                           and (bin_name.lower() in process_name),
                            callback=lambda process_name, proc: proc.kill())

        reload_cmd = sdk.read_file_content(".goserver.runcmd")
        sdk.run_shell(reload_cmd)
        print(reload_cmd)
        return


def javaserver():
    parser = argparse.ArgumentParser()
    parser.add_argument("--restart", action="store_true", help="restart server")
    parser.add_argument("--stop", action="store_true", help="stop server")
    parser.add_argument("--status", action="store_true", help="show server status")
    parser.add_argument("--config", action="store_true", help="show server config")
    parser.add_argument("--reload", action="store_true", help="reload server")
    parser.add_argument("--env", type=str, default="test", help="set server env")
    parser.add_argument("-p", "--port", type=int, help="set server port")
    parser.add_argument("-m", "--memory", type=int, help="set server memory")
    parser.add_argument("-D", "--data", type=str, nargs="*", help="set server data")
    parser.add_argument("-a", "--params", type=str, nargs="*", help="set server param")
    parser.add_argument("-P", "--debug", action="store_true", help="run server in debug mode")
    parser.add_argument("-l", "--log", action="store_true", help="extra log in javaserver log")
    parser.add_argument("-d", "--daemon", action="store_true", help="run server in daemon")
    parser.add_argument("app", type=str, help="jar package or all")
    args = parser.parse_args()

    java_version = sdk.java_version()
    app: str = args.app

    if args.restart:
        if not os.path.exists(app):
            raise FileNotFoundError(f"{app} not found")
        if not app.endswith(".jar"):
            raise FileNotFoundError(f"{app} is not a jar package.")
        dir_name = os.path.dirname(app)
        jar = os.path.basename(app)
        os.chdir(dir_name)
        sdk.iterate_process(condition=lambda process_name: ('launcher=javaserver' in process_name)
                                                           and (jar.lower() in process_name),
                            callback=lambda process_name, proc: proc.kill())
        cmd = "java -Dlauncher=javaserver"
        if args.memory is not None:
            cmd = f"{cmd} -Xms{args.memory} -Xmx{args.memory}"
        if args.debug:
            debug_port = sdk.find_available_port(8100, 8200)
            if java_version >= 9:
                cmd = f"{cmd} -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:{debug_port}"
            else:
                cmd = f"{cmd} -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address={debug_port}"
        cmd = f"{cmd} -Dspring.profiles.active={args.env} -Drcc.envName={args.env} -Dfile.encoding=UTF-8"
        if args.data is not None:
            for data in args.data:
                cmd = f"{cmd} -D{data}"
        if java_version >= 9:
            cmd = f"{cmd} --add-opens java.base/java.io=ALL-UNNAMED --add-opens java.base/java.lang=ALL-UNNAMED " \
                  f"--add-opens java.base/java.math=ALL-UNNAMED --add-opens java.base/java.net=ALL-UNNAMED " \
                  f"--add-opens java.base/java.nio=ALL-UNNAMED --add-opens java.base/java.security=ALL-UNNAMED " \
                  f"--add-opens java.base/java.text=ALL-UNNAMED --add-opens java.base/java.time=ALL-UNNAMED " \
                  f"--add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/jdk.internal.access=ALL-UNNAMED"
        cmd = f"{cmd} -jar {jar}"
        if args.port is not None and args.port > 0:
            cmd = f"{cmd} --server.port={args.port}"
        if args.params is not None:
            for param in args.params:
                cmd = f"{cmd} --{param}"
        if args.daemon:
            if args.log:
                log_path = "../../javaserver-logs"
                if not os.path.exists(log_path):
                    os.mkdir(log_path)
                basename, _ = os.path.splitext(jar)
                log_file = f"{log_path}/{basename}.log"
                cmd = f"{cmd} >>{log_file} 2>&1 &"
            else:
                cmd = f"{cmd} >/dev/null 2>&1 &"
        sdk.run_shell(cmd)
        sdk.write_file_content(".javaserver.runcmd", cmd)
        print(cmd)
        return

    if args.stop:
        if app.lower() == "all":
            sdk.iterate_process(condition=lambda process_name: ('launcher=javaserver' in process_name),
                                callback=lambda process_name, proc: proc.kill())
        else:
            sdk.iterate_process(condition=lambda process_name: ('launcher=javaserver' in process_name)
                                                               and (app.lower() in process_name),
                                callback=lambda process_name, proc: proc.kill())
        return

    if args.status:
        jar_pattern = r'[-]jar\s+(\S+\.jar)'
        profile_pattern = r'-Dspring\.profiles\.active=([^ ]+)'

        def print_server_info(process_name, proc: psutil.Process):
            jar_match = re.search(jar_pattern, process_name)
            profile_match = re.search(profile_pattern, process_name)
            server_name = jar_match.group(1) if jar_match else None
            server_env = profile_match.group(1) if profile_match else None
            ports = sdk.get_process_listen_ports(proc.pid)
            print(f"server({server_name}) run env: {server_env}, run pid: {proc.pid}, run port: {ports}")

        if app.lower() == "all":
            sdk.iterate_process(condition=lambda process_name: ('launcher=javaserver' in process_name),
                                callback=print_server_info)
        else:
            sdk.iterate_process(condition=lambda process_name: ('launcher=javaserver' in process_name)
                                                               and (app.lower() in process_name),
                                callback=print_server_info)
        return

    if args.config:
        if app.lower() == "all":
            sdk.iterate_process(condition=lambda process_name: ('launcher=javaserver' in process_name),
                                callback=lambda process_name, proc: print(process_name))
        else:
            sdk.iterate_process(condition=lambda process_name: ('launcher=javaserver' in process_name)
                                                               and (app.lower() in process_name),
                                callback=lambda process_name, proc: print(process_name))
        return

    if args.reload:
        if not os.path.exists(app):
            raise FileNotFoundError(f"{app} not found")
        if not app.endswith(".jar"):
            raise FileNotFoundError(f"{app} is not a jar package.")
        dir_name = os.path.dirname(app)
        jar = os.path.basename(app)
        os.chdir(dir_name)

        reload_cmd = sdk.read_file_content(".javaserver.runcmd")
        sdk.iterate_process(condition=lambda process_name: ('launcher=javaserver' in process_name)
                                                           and (jar.lower() in process_name),
                            callback=lambda process_name, proc: proc.kill())

        sdk.run_shell(reload_cmd)
        print(reload_cmd)
        return


def http_file_server():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', type=str, required=False, default=os.getcwd())
    parser.add_argument('-p', '--port', type=int, required=False, default=8899)
    parser.add_argument('-d', '--daemon', action='store_true')
    sub_parser = parser.add_subparsers(dest='mode')
    auth = sub_parser.add_parser('auth', help='use auth mode')
    auth.add_argument('--username', type=str, required=True)
    auth.add_argument('--password', type=str, required=True)
    args = parser.parse_args()

    def modification_date(filename):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(filename)))

    class HttpFileRequestHandler(SimpleHTTPRequestHandler):
        def _send_auth_request(self):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Protected"')
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"Authentication required.")

        def _is_authenticated(self):
            if args.mode == "auth":
                auth_header = self.headers.get("Authorization")
                return auth_header == sdk.basic_auth(args.username, args.password)
            else:
                return True

        def parse_request(self):
            if not super().parse_request():
                return False
            if not self._is_authenticated():
                self._send_auth_request()
                return False
            return True

        def log_message(self, format, *args):
            pass

        def guess_type(self, path):
            url_parsed = urlparse(self.path)
            if url_parsed.query.lower() == 'download':
                return 'application/octet-stream'
            return super().guess_type(path)

        def do_POST(self):
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                result, info = self.deal_post_data()
            except Exception:
                result, info = False, 'Unknown server error'
            self.log_message('%s %s by: %s', result, info, self.client_address)
            enc = sys.getfilesystemencoding()
            r = ['<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">',
                 "<html>\n<title>Upload Result Page</title>\n", "<body>\n<h2>Upload Result Page</h2>\n", "<hr>\n"]
            if result:
                r.append("<strong>Success:</strong>")
            else:
                r.append("<strong>Failed:</strong>")
            r.append(info)
            r.append(f"<br><a href=\"{self.headers['referer']}\">back</a>")
            r.append(f"<hr><small>last upload at: {now}</small></body>\n</html>\n")
            encoded = '\n'.join(r).encode(enc)
            f = io.BytesIO()
            f.write(encoded)
            f.seek(0)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", f"text/html; charset={enc}")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            if f:
                self.copyfile(f, self.wfile)
                f.close()

        def deal_post_data(self):
            boundary = self.headers.get('content-type').split("=")[1].encode("utf-8")
            remainders = int(self.headers['content-length'])
            line = self.rfile.readline()
            remainders -= len(line)
            if boundary not in line:
                return False, "Content not begin with boundary"
            line = self.rfile.readline()
            remainders -= len(line)
            fn = re.findall(r'Content-Disposition.*name="file"; filename="(.*)"', line.decode("utf-8"))
            if not fn:
                return False, "Can't find out file name..."
            path = self.translate_path(self.path)
            osType = platform.system()
            try:
                if osType == "Linux":
                    fn = os.path.join(path, fn[0])
                else:
                    fn = os.path.join(path, fn[0].decode("utf-8"))
            except Exception as e:
                return False, "Please do not use Chinese file name, or use IE to upload files with Chinese name."
            if os.path.exists(fn):
                os.remove(fn)
            line = self.rfile.readline()
            remainders -= len(line)
            line = self.rfile.readline()
            remainders -= len(line)
            try:
                out = open(fn, 'wb')
            except IOError:
                return False, "Can't create file to write, do you have permission to write?"
            pre_line = self.rfile.readline()
            remainders -= len(pre_line)
            while remainders > 0:
                line = self.rfile.readline()
                remainders -= len(line)
                if boundary in line:
                    pre_line = pre_line[0:-1]
                    if pre_line.endswith('\r'.encode("utf-8")):
                        pre_line = pre_line[0:-1]
                    out.write(pre_line)
                    out.close()
                    return True, f"File '{fn}' upload success!"
                else:
                    out.write(pre_line)
                    pre_line = line
            return False, "Unexpected end of data."

        def list_directory(self, path):
            try:
                dir_list = os.listdir(path)
            except OSError:
                self.send_error(HTTPStatus.NOT_FOUND, "No permission to list directory")
                return None
            dir_list.sort(key=lambda a: a.lower())
            r = []
            try:
                display_path = urllib.parse.unquote(self.path)
            except UnicodeDecodeError:
                display_path = urllib.parse.unquote(path)
            display_path = html.escape(display_path, quote=False)
            enc = sys.getfilesystemencoding()
            title = f'Directory listing for {display_path}'
            r.append('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">')
            r.append('<html>\n<head>')
            r.append(f'<meta http-equiv="Content-Type" content="text/html; charset={enc}">')
            r.append(f'<title>{title}</title>\n</head>')
            r.append(f'<body>\n<h1>{title}</h1>')
            r.append('<hr>')
            r.append('<form ENCTYPE="multipart/form-data" method="post">')
            r.append('<input name="file" type="file"/>')
            r.append('<input type="submit" value="upload"/>')
            r.append('&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp')
            r.append('<input type="button" value="HomePage" onClick="location=\'/\'">')
            r.append('</form>')
            r.append('<hr>')
            r.append('<table width="100%" cellspacing="0" cellpadding="5">')
            for name in dir_list:
                fullname = os.path.join(path, name)
                if os.path.isdir(fullname):
                    display_name = name + "/"
                    link_name = name + "/"
                    download_name = ""
                else:
                    display_name = name
                    link_name = name
                    download_name = urllib.parse.quote(link_name) + "?download"
                filename = os.getcwd() + '/' + display_path + display_name
                r.append(f'<tr>'
                         f'<td width="40%%"><a href="{urllib.parse.quote(link_name)}">{html.escape(display_name)}</a></td>'
                         f'<td width="20%%"><a href="{download_name}">下载</a></td>'
                         f'<td width="20%%">{humanize.naturalsize(os.path.getsize(filename))}</td>'
                         f'<td width="20%%">{modification_date(filename)}</td>'
                         f'</tr>')
            r.append('</table>')
            r.append('<hr>')
            r.append("</body>")
            r.append("</html>")
            encoded = '\n'.join(r).encode(enc)
            f = io.BytesIO()
            f.write(encoded)
            f.seek(0)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", f"text/html; charset={enc}")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            return f

    if not os.path.exists(args.dir):
        raise RuntimeError(f"{args.dir} is not exists")
    else:
        os.chdir(args.dir)

    flag = os.path.basename(os.path.realpath(args.dir))
    http_server = sdk.HttpServer(port=args.port, name=f"HttpFileServer:{args.port}:{flag}")
    http_server.set_request_handler_class(HttpFileRequestHandler)
    http_server.use_threading_http_server(True)
    http_server.start(daemon=args.daemon)


def file_deploy_server():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int, default=8880)
    parser.add_argument("-d", "--daemon", action="store_true")
    parser.add_argument("--dir", type=str, required=True, help="file to save directory")
    parser.add_argument("--child_dir", action="store_true", help="need to make child dir?")
    parser.add_argument("--dec", action="store_true", help="need to decompress?")
    parser.add_argument("--flag", type=str, required=True, help="server flag")
    parser.add_argument("--cmd", type=str, required=False, help="if succeed command to run")
    args = parser.parse_args()

    file_dir = args.dir
    if not os.path.exists(file_dir):
        raise RuntimeError(f"{file_dir} is not exists")

    def post_method(handler):
        parse = urlparse(handler.path)
        if parse.path == '/deploy':
            form = cgi.FieldStorage(fp=handler.rfile, headers=handler.headers,
                                    environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': handler.headers['Content-Type']})
            uploaded_file = form['file']
            file_name = os.path.basename(uploaded_file.filename)

            if args.child_dir:
                filename_without_ext, _ = os.path.splitext(file_name)
                file_home = os.path.join(file_dir, filename_without_ext)
                if not os.path.exists(file_home):
                    os.mkdir(file_home)
            else:
                file_home = file_dir

            file_path = os.path.join(file_home, file_name)
            with open(file_path, 'wb') as f:
                f.write(uploaded_file.file.read())

            if args.dec:
                file_home = os.path.join(file_home, Path(file_name).with_suffix('').stem)
                if os.path.exists(file_home):
                    shutil.rmtree(file_home)
                os.mkdir(file_home)
                tar_cmd = f'tar -xzvf {file_path} -C {file_home}'
                sdk.run_shell(tar_cmd)
                os.remove(file_path)

            if args.cmd:
                params = []
                for key in form.keys():
                    items = form[key] if isinstance(form[key], list) else [form[key]]
                    params.extend([kv for item in items if not item.filename for kv in (key, item.value)])

                cmd = args.cmd
                cmd = f"{cmd}".replace("{FILE_HOME}", f"{file_home}")
                cmd = f"{cmd}".replace("{FILE_PATH}", f"{file_path}")
                cmd = f"{cmd}".replace("{FILE_NAME}", f"{file_name}")
                cmd = f"{cmd} {' '.join(params)}"
                process = sdk.run_bash(cmd)
                handler.ok(process.stdout)
            else:
                handler.ok("success.")
        else:
            handler.error("the route is invalid")

    http_server = sdk.HttpServer(port=args.port, name=f"FileDeployServer:{args.port}:{args.flag}")
    http_server.set_post_method(method=post_method)
    http_server.start(daemon=args.daemon)


def file_deploy():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=str, required=False)
    parser.add_argument("--url", type=str, required=True)
    parser.add_argument("params", type=str, nargs="*")
    args = parser.parse_args()

    try:
        url = sdk.get_config(args.url)
    except KeyError:
        url = args.url

    need_remove = False
    if args.file:
        if not os.path.exists(args.file):
            raise RuntimeError(f"{args.file} is not exists")
        file = args.file
    else:
        with sdk.TransactionalReplacer(".pybin_file_deploy.json"):
            project = os.path.basename(os.getcwd())
            file = f'{project}.tar.gz'
            tar_command = f'tar --no-mac-metadata -czf {file} *'
            result = sdk.run_shell(tar_command)
            if result.returncode == 0:
                need_remove = True
                print("file has been successfully packed.")
            else:
                raise RuntimeError("packets has failed.")

    try:
        print(f"ready to deploy file: {file}...", end="\n\n")
        response = sdk.upload_file_with_curl(url, file, params=args.params)
        print(f"\n\n{response}\n{sdk.format_timestamp()}")
    finally:
        if need_remove:
            os.remove(file)


def gko():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=str)
    args = parser.parse_args()

    path: str = args.path
    if not path.startswith("gko3://"):
        protocol = sdk.get_config("protocol")
        path = f"{protocol}{path}"

    cmd = f"gko3 down --source {path}"
    process = sdk.run_shell(cmd)
    print(process.stdout)


def opssh():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bns", type=str, required=True, help="bns name or path")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--concurrent", type=int, default=20, help="concurrent execute, default 20")
    parser.add_argument("--username", type=str, required=False)
    parser.add_argument("cmd", type=str)
    args = parser.parse_args()

    app = args.bns
    limit = args.limit
    username = args.username
    separator = '=' * 20
    red = '\033[91m'
    reset = '\033[0m'

    try:
        bns = sdk.get_config(app)
    except KeyError:
        bns = app
    services = sdk.parse_bns(bns)
    tasks = services if limit is None or limit > len(services) else services[:limit]

    def handle(lock, task):
        if username:
            instance = f"{username}@{task['instance']}"
        else:
            instance = task['instance']
        colored_name = f"{red}{instance}{reset}"
        cmd = f'ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no -o ConnectionAttempts=2 -o ' \
              f'ConnectTimeout=4 -n --matrix {instance} "{args.cmd}" '
        try:
            process = sdk.run_shell(cmd)
            with lock:
                print(f"{separator} {colored_name} {separator}")
                print(process.stdout)
        except Exception as e:
            with lock:
                print(f"{separator} {colored_name} {separator}")
                print(f'ssh {instance} returned {str(e)}')

        time.sleep(1)

    sdk.concurrent_execute(tasks=tasks, handler=handle, concurrent=args.concurrent)


def hadooproxy():
    parser = argparse.ArgumentParser()
    parser.add_argument("name", type=str)
    parser.add_argument("fs", type=str, choices=['fs'])
    parser.add_argument("type", type=str)
    parser.add_argument("paths", type=str, nargs="+")
    args = parser.parse_args()

    hadoop_client = sdk.get_config('hadoop_client')

    if args.name != "default":
        config = sdk.get_config(args.name)
        paths = args.paths
    else:
        config = {}
        paths = []
        for url in args.paths:
            parsed_url = urlparse(url)
            if parsed_url.scheme and parsed_url.netloc:
                ugi, hostname = parsed_url.netloc.split("@", 1)
                config['afs'] = f"{parsed_url.scheme}://{hostname}"
                config['ugi'] = ugi
                paths.append(parsed_url.path)
            else:
                paths.append(url)
        if not config:
            parser.exit(1, parser.format_help())

    for i in range(len(paths)):
        if paths[i].startswith("/home/volume/"):
            paths[i] = sdk.remove_path_prefix_part(paths[i], 3)

    path = " ".join(paths)

    cmd = f"-Dfs.default.name={config['afs']} {args.type} {path}"
    if args.type != "-ls" and args.type != "-get" and args.type != "-cat":
        confirm = input(f"Whether to confirm the operation? ({cmd})[Y/N]")
        if confirm.upper() != 'Y':
            print("have canceled.")
            sys.exit()

    cmd = f"{hadoop_client} fs -Dhadoop.job.ugi={config['ugi']} {cmd}"

    process = sdk.run_shell(cmd)
    print(process.stdout)


def pip_search():
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=str)
    args = parser.parse_args()

    cmds = [sys.executable, "-m", "pip", "install", f"{args.package}=="]
    process = subprocess.run(cmds, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, universal_newlines=True)
    match = re.search(r"from versions: ([^)]+)", process.stdout)
    print(f"Available versions:")
    if match:
        print(match.group(1))


def manifest():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hadoop", type=str, required=True, help="hadoop fs -Dhadoop.job.ugi=xx -Dfs.default.name=xx")
    parser.add_argument("--start_time", type=str, required=True, help="YmdHm, example: 202409041540")
    parser.add_argument("--end_time", type=str, required=True, help="YmdHm, example: 202409051200")
    parser.add_argument("--step", type=int, required=True, help="incr minutes, example: 5")
    parser.add_argument("--path", type=str, required=True)
    parser.add_argument("--file", type=str, default="manifest", help="default: manifest")
    parser.add_argument("--touchz", action="store_true")
    parser.add_argument("--concurrent", type=int, default=10, help="concurrent execute, default 10")
    args = parser.parse_args()

    current_time = datetime.strptime(args.start_time, "%Y%m%d%H%M")
    end_time = datetime.strptime(args.end_time, "%Y%m%d%H%M")
    cmds = []
    while current_time <= end_time:
        date_part = current_time.strftime("%Y%m%d")
        time_part = current_time.strftime("%H%M")
        file = os.path.join(args.path, date_part, time_part, args.file)
        cmd = f"{args.hadoop} -touchz {file}"
        cmds.append(cmd)
        current_time += timedelta(minutes=args.step)

    def handle(lock, task):
        if args.touchz is True:
            process = sdk.run_shell(task)
            with lock:
                print(task)
                print(process.stdout)
        else:
            with lock:
                print(task)

    sdk.concurrent_execute(tasks=cmds, handler=handle, concurrent=args.concurrent)


def concurrency():
    parser = argparse.ArgumentParser()
    parser.add_argument("--concurrent", type=int, default=10, help="concurrent number, default 10")
    parser.add_argument("--max_times", type=int, required=True, help="max execute times")
    parser.add_argument("cmd", type=str, help="execute cmd")
    args = parser.parse_args()

    tasks = []
    for i in range(args.max_times):
        tasks.append(args.cmd)

    def handle(lock, task):
        process = sdk.run_shell(task)
        with lock:
            print(process.stdout)

    sdk.concurrent_execute(tasks=tasks, handler=handle, concurrent=args.concurrent)


def datetime_calc():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=str, nargs="*")
    args = parser.parse_args()

    if args.input is not None:
        date_times = args.input
    else:
        date_times = sys.stdin.read().strip().split('\n')

    for date_time in date_times:
        if date_time.isdigit():
            ts = int(date_time) / 1000 if int(date_time) > 1e12 else int(date_time)
            print(datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"))
        else:
            formats = [
                "%Y-%m-%d", "%Y/%m/%d", "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S", "%Y%m%d", "%Y%m%d%H%M%S",
            ]
            for fmt in formats:
                try:
                    print(int(datetime.strptime(date_time, fmt).timestamp()))
                except ValueError:
                    continue


def read_excel():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sheet", type=int, default=0)
    parser.add_argument("--header", type=int)
    parser.add_argument("--read_cols", type=int, nargs='+')
    parser.add_argument("--skip_rows", type=int, nargs='+')
    parser.add_argument("--read_rows", type=int)
    parser.add_argument("excel", type=str)
    args = parser.parse_args()

    df = pd.read_excel(args.excel, engine="openpyxl", sheet_name=args.sheet, header=args.header, usecols=args.read_cols,
                       skiprows=args.skip_rows, nrows=args.read_rows)

    for value in df.values:
        print("\t".join(map(str, value)))


def write_excel():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--separator', type=str, default='\t')
    parser.add_argument("excel", type=str)
    args = parser.parse_args()

    data = [line.strip().split(args.separator) for line in sys.stdin if line.strip()]
    df = pd.DataFrame(data)

    df.to_excel(args.excel, index=False, header=False)


def table2md():
    parser = argparse.ArgumentParser()
    parser.add_argument("table", type=str, nargs="?")
    args = parser.parse_args()

    if args.table is not None:
        lines = sdk.read_file(args.table)
    else:
        lines = sys.stdin.read().splitlines()

    headers = lines[0].split('\t')
    rows = []
    for line in lines[1:]:
        rows.append(line.split('\t'))
    print(tabulate(rows, headers=headers, tablefmt="github"))


def istock():
    parser = argparse.ArgumentParser()
    parser.add_argument('--min', type=float, required=False)
    parser.add_argument('code', type=str)
    args = parser.parse_args()

    url = sdk.get_config("url")
    url = url.format(code=args.code)
    resp = requests.get(url)
    data = resp.text.split("~")
    if len(data) <= 3:
        raise RuntimeError('query stock failed')

    price = data[3]
    if args.min is None or Decimal(price) > Decimal(args.min):
        print(f"{args.code}: {price}")


def tail_f():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', type=str)
    args = parser.parse_args()

    file_path = os.path.abspath(args.file)
    file_name = os.path.basename(file_path)
    file_dir = os.path.dirname(file_path)

    inotify = INotify()
    wd_dir = None
    f: Optional[TextIO] = None

    def open_file():
        nonlocal f
        try:
            f = open(file_path, "r", encoding="utf-8")
            f.seek(0, os.SEEK_END)
            print(f"the file has been created: {file_path}\n")
        except FileNotFoundError:
            f = None

    def watch_dir():
        nonlocal wd_dir
        try:
            wd_dir = inotify.add_watch(file_dir, flags.CREATE | flags.DELETE | flags.MOVED_TO | flags.MOVED_FROM)
        except FileNotFoundError:
            wd_dir = None

    watch_dir()
    open_file()

    while True:
        if wd_dir is None or not os.path.exists(file_dir):
            while not os.path.exists(file_dir):
                time.sleep(0.5)
            watch_dir()

        if f is None:
            open_file()

        if f:
            line = f.readline()
            while line:
                print(line, end="")
                line = f.readline()

        for e in inotify.read(timeout=100):
            if e.name == file_name and e.mask & (flags.CREATE | flags.MOVED_TO):
                open_file()
            if e.name == file_name and e.mask & (flags.DELETE | flags.MOVED_FROM) and f:
                f.close()
                f = None
                print(f"\nthe file has been deleted: {file_path}")

        time.sleep(0.1)


if __name__ == "__main__":
    sdk.run_main()
