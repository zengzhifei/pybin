#!/usr/bin/env python3

import argparse
import cgi
import glob
import html
import inspect
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib
from datetime import datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

import humanize
import psutil as psutil
import requests as requests

import sdk
from __about__ import __version__, __author__
from ann import RuntimeEnv, RuntimeKey, RuntimeMode, runtime


def pybin():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--version", action="store_true", help="show version")
    parser.add_argument("-a", "--author", action="store_true", help="show author")
    parser.add_argument("-f", "--function", action="store_true", help="show function")
    parser.add_argument("-i", "--install", "--update", action="store_true", help="install or update pybin")
    parser.add_argument("-c", "--config", type=str, nargs="+", help="show config")
    args = parser.parse_args()

    if args.install:
        source_path = os.environ.get("PYBIN_SOURCE_PATH")
        os.chdir(source_path)
        process = sdk.run_shell(f"{sys.executable} install.py")
        print(process.stdout)
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

    if args.version:
        print(__version__)
        return

    if args.author:
        print(__author__)
        return

    functions = "\n".join(sorted(["  " + func['name'] for functions in funcs().values() for func in functions]))
    if args.function:
        print(functions)
        return

    print(f"version: {__version__}")
    print(f"author: {__author__}")
    print(f"function: \n{functions}")


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
        target_dir, target_item = max(filtered_data.items(), key=lambda x: (x[1]['dir_count'], x[1]['dir_time']))

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
def gomysql():
    parser = argparse.ArgumentParser()
    parser.add_argument("tag", type=str)
    parser.add_argument("cmds", type=str, nargs="*")
    args = parser.parse_args()

    config = sdk.get_config(args.tag)

    if args.cmds is None:
        cmd = f'mysql -A {config} --default-character-set=utf8'
    else:
        cmd = f'mysql -A {config} --default-character-set=utf8 {" ".join(args.cmds)}'

    print(cmd)

    sys.exit(250)


@runtime(env=RuntimeEnv.SHELL, shell_exit_code=250)
def goredis():
    parser = argparse.ArgumentParser()
    parser.add_argument("tag", type=str)
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
        cmd = f'redis-cli {conn} --raw {" ".join(args.cmds)}'

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


def dusort():
    parser = argparse.ArgumentParser()
    parser.add_argument('--depth', type=int, default=1)
    args = parser.parse_args()

    result = sdk.run_shell(f"du -h --max-depth={args.depth} | sort -rh")
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
    parser.add_argument("--oldemail", required=True, type=str)
    parser.add_argument("--newname", required=True, type=str)
    parser.add_argument("--newemail", required=True, type=str)
    args = parser.parse_args()

    cmd = f"""
        git filter-branch -f --env-filter '
            OLD_EMAIL="'{args.oldemail}'"
            CORRECT_NAME="'{args.newname}'"
            CORRECT_EMAIL="'{args.newemail}'"
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


def runcmd():
    parser = argparse.ArgumentParser()
    parser.add_argument("name", type=str)
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
    result = sdk.run_shell(cmd)
    print(result.stdout)


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
    parser.add_argument("--text", type=str, nargs="*")
    parser.add_argument("--link", type=str, nargs="*")
    parser.add_argument("--label", type=str, nargs="*")
    parser.add_argument("--image", type=str)
    parser.add_argument("--at", type=str, nargs="*")
    parser.add_argument("--at-all", action="store_true")
    args = parser.parse_args()

    url = sdk.get_config("url")
    header = {'toid': list(map(int, sdk.get_config("toid").split(",")))}
    body = []
    if args.text is not None:
        for text in args.text:
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
        parser.exit(1, parser.format_help())

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


def csum():
    total_sum = 0
    for line in sys.stdin:
        number = int(line.strip())
        total_sum += number

    print(total_sum)


def mod():
    parser = argparse.ArgumentParser()
    parser.add_argument('dividend', type=int)
    args = parser.parse_args()

    for line in sys.stdin:
        divisor = int(line.strip())
        print(divisor % args.dividend)


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


def ikill():
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


def http_file_server():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', type=str, required=False, default=os.getcwd())
    parser.add_argument('-p', '--port', type=int, required=False, default=8899)
    parser.add_argument('-d', '--daemon', action='store_true')
    args = parser.parse_args()

    def modification_date(filename):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(filename)))

    class HttpFileRequestHandler(SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_POST(self):
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result, info = self.deal_post_data()
            print(result, info, "by: ", self.client_address)
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
            r.append('<hr>\n')
            r.append('<form ENCTYPE="multipart/form-data" method="post">')
            r.append('<input name="file" type="file"/>')
            r.append('<input type="submit" value="upload"/>')
            r.append('&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp')
            r.append('<input type="button" value="HomePage" onClick="location=\'/\'">')
            r.append('</form>\n')
            r.append('<hr>\n<ul>')
            for name in dir_list:
                fullname = os.path.join(path, name)
                display_name = link_name = name
                if os.path.isdir(fullname):
                    display_name = name + "/"
                    link_name = name + "/"
                if os.path.islink(fullname):
                    display_name = name + "@"
                filename = os.getcwd() + '/' + display_path + display_name
                r.append(f'<table><tr>'
                         f'<td width="60%%"><a href="{urllib.parse.quote(link_name)}">{html.escape(display_name)}</a></td>'
                         f'<td width="20%%">{humanize.naturalsize(os.path.getsize(filename))}</td>'
                         f'<td width="20%%">{modification_date(filename)}</td>'
                         f'</tr></table>\n')
            r.append("\n<hr>\n</body>\n</html>\n")
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

    http_server = sdk.HttpServer(port=args.port, name=f"HttpFileServer:{args.port}")
    http_server.set_request_handler_class(HttpFileRequestHandler)
    http_server.use_threading_http_server(True)
    http_server.start(daemon=args.daemon)


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


def java_deploy_server():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int, default=8501)
    parser.add_argument("-d", "--daemon", action="store_true")
    parser.add_argument("-r", "--runtime", type=str, required=True)
    args = parser.parse_args()

    def post_method(handler: BaseHTTPRequestHandler):
        parse = urlparse(handler.path)
        if parse.path == '/deploy':
            form = cgi.FieldStorage(fp=handler.rfile, headers=handler.headers,
                                    environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': handler.headers['Content-Type']})
            uploaded_file = form['file']
            filename = os.path.basename(uploaded_file.filename)
            filename_without_ext, _ = os.path.splitext(filename)
            file_dir = os.path.join(args.runtime, filename_without_ext)
            if not os.path.exists(file_dir):
                os.mkdir(file_dir)
            filepath = os.path.join(str(file_dir), filename)
            with open(filepath, 'wb') as f:
                f.write(uploaded_file.file.read())

            cmd = f"javaserver --restart --debug --log -d {filepath}"
            if parse.query:
                params = parse.query.split("&")
                for param in params:
                    pair = param.split("=", 1)
                    cmd = f"{cmd} {pair[0]} {pair[1]}"
            process = sdk.run_shell(cmd)
            handler.ok(process.stdout)
        else:
            handler.error("the route is invalid")

    if not os.path.exists(args.runtime):
        raise RuntimeError(f"{args.runtime} is not exists")

    http_server = sdk.HttpServer(port=args.port, name=f"JavaDeployServer:{args.port}")
    http_server.set_post_method(method=post_method)
    http_server.start(daemon=args.daemon)


def java_deploy():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", type=str, required=True)
    parser.add_argument("pkg", type=str, nargs="?")
    args = parser.parse_args()

    all_jar_files = glob.glob(os.path.join(os.getcwd(), '**', '*.jar'), recursive=True)
    all_jar_files = [jar for jar in all_jar_files if 'source' not in os.path.basename(jar)]
    all_jar_files_str = '\n'.join([path.replace(os.getcwd(), '') for path in all_jar_files])
    if args.pkg is None:
        print(all_jar_files_str)
        return

    jar_files = [jar for jar in all_jar_files if args.pkg in os.path.basename(jar)]
    jar_files_str = '\n'.join([path.replace(os.getcwd(), '') for path in jar_files])

    if len(jar_files) > 1:
        raise RuntimeError(f"the search result is more than one, please choose one.\n{jar_files_str}")

    if len(jar_files) < 1:
        raise RuntimeError(f"the package: {args.pkg} is not exist or choose error.\n{all_jar_files_str}")

    package = jar_files[0]
    application_yaml = f"{os.path.dirname(package)}/classes/application.yml"
    application_prop = f"{os.path.dirname(package)}/classes/application.properties"
    if not os.path.exists(application_yaml) and not os.path.exists(application_prop):
        raise RuntimeError(f"the package: {args.pkg} maybe not a application.")

    print(f"ready to deploy package: {package}...", end="\n\n")

    response = sdk.upload_file_with_curl(args.url, package)
    print(f"\n\n{response}")


def file_deploy_server():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int, default=8502)
    parser.add_argument("-d", "--daemon", action="store_true")
    parser.add_argument("--dir", type=str, required=True, help="file to save directory")
    parser.add_argument("--dec", action="store_true", help="need to decompress?")
    parser.add_argument("--cmd", type=str, required=False, help="if succeed command to run")
    args = parser.parse_args()

    def post_method(handler: BaseHTTPRequestHandler):
        parse = urlparse(handler.path)
        if parse.path == '/deploy':
            form = cgi.FieldStorage(fp=handler.rfile, headers=handler.headers,
                                    environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': handler.headers['Content-Type']})
            uploaded_file = form['file']
            filename = os.path.basename(uploaded_file.filename)
            file_dir = args.dir
            if not os.path.exists(file_dir):
                os.mkdir(file_dir)
            filepath = os.path.join(file_dir, filename)
            file_home = os.path.join(file_dir, Path(filename).with_suffix('').stem)
            with open(filepath, 'wb') as f:
                f.write(uploaded_file.file.read())

            if args.dec:
                if os.path.exists(file_home):
                    shutil.rmtree(file_home)
                os.mkdir(file_home)
                tar_cmd = f'tar -xzvf {filepath} -C {file_home}'
                sdk.run_shell(tar_cmd)
                os.remove(filepath)

            if args.cmd:
                process = sdk.run_shell(args.cmd)
                handler.ok(process.stdout)
            else:
                handler.ok("success.")
        else:
            handler.error("the route is invalid")

    if not os.path.exists(args.dir):
        raise RuntimeError(f"{args.dir} is not exists")

    http_server = sdk.HttpServer(port=args.port, name=f"FileDeployServer:{args.port}")
    http_server.set_post_method(method=post_method)
    http_server.start(daemon=args.daemon)


def file_deploy():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=str, required=False)
    parser.add_argument("--url", type=str, required=True)
    args = parser.parse_args()

    need_remove = False
    if args.file:
        if not os.path.exists(args.file):
            raise RuntimeError(f"{args.file} is not exists")
        file = args.file
    else:
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
        response = sdk.upload_file_with_curl(args.url, file)
        print(f"\n\n{response}")
    finally:
        if need_remove:
            os.remove(file)


def php_deploy():
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", type=str, required=True)
    parser.add_argument("--url", type=str, required=True)
    args = parser.parse_args()

    project = os.path.basename(os.getcwd())
    if "beco" != project:
        raise RuntimeError("current dir is not support")

    env = args.env

    modify_list = [
        {
            "file": "app/beco/service/rt/Global.php",
            "old_text": 'const ENGINE_SERVICE_NAME = "service_rts_engine"',
            "new_text": f'const ENGINE_SERVICE_NAME = "service_rts_engine_{env}"'
        },
        {
            "file": "app/beco/service/rt/Global.php",
            "old_text": 'throw new LogicException("BP账号没有发布权限")',
            "new_text": '//throw new LogicException("BP账号没有发布权限")'
        },
        {
            "file": "app/beco/service/rt/Global.php",
            "old_text": 'throw new LogicException("BP账号没有订阅权限")',
            "new_text": '//throw new LogicException("BP账号没有订阅权限")'
        },
        {
            "file": "app/beco/service/rt/BaseHtap.php",
            "old_text": 'const DORIS_CLUSTER_BJ = "bj"',
            "new_text": 'const DORIS_CLUSTER_BJ = "sandbox"'
        },
        {
            "file": "app/beco/service/rt/BaseHtap.php",
            "old_text": 'const DORIS_CLUSTER_BD = "bd"',
            "new_text": 'const DORIS_CLUSTER_BD = "sandbox"'
        },
    ]

    for modification in modify_list:
        sdk.modify_file(modification["file"], modification["old_text"], modification["new_text"])

    package = 'beco.tar.gz'
    tar_command = f'tar --no-mac-metadata -czf {package} "app" "conf" "data" "test"'
    result = sdk.run_shell(tar_command)

    if result.returncode == 0:
        print(f"packets has been successfully packed. connected engine: {env}")
    else:
        raise RuntimeError("packets has failed.")

    for modification in modify_list:
        sdk.modify_file(modification["file"], modification["new_text"], modification["old_text"])

    print(f"ready to deploy package: {package}...", end="\n\n")

    response = sdk.upload_file_with_curl(args.url, package)

    print(f"\n\n{response}")


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


def pass_helper():
    parser = argparse.ArgumentParser()
    parser.add_argument("--passId", required=False, action="store_true")
    parser.add_argument("--mobile", required=False, action="store_true")
    parser.add_argument("input", type=str)
    args = parser.parse_args()

    passId = ''
    username = ''
    mobile = ''
    if args.passId or args.mobile:
        if args.passId:
            passId = args.input
        elif args.mobile:
            mobile = args.input
    else:
        if re.match(r'^1[3-9]\d{9}$', args.input):
            mobile = args.input
        elif re.match(r'^\d+$', args.input):
            passId = args.input
        else:
            username = args.input

    bns = sdk.get_config("bns")
    url: str = sdk.get_config("url")
    services = sdk.parse_bns(bns)
    host = f"{services[0]['ip']}:{services[0]['port']}"
    url = url.format(host, passId, username, mobile)
    headers = {
        'AMIS_ROLES': sdk.get_config("roles").encode('utf-8').decode('latin-1'),
        'AMIS_USER_TYPE': sdk.get_config("user_type"),
        'AMIS_USER': sdk.get_config("user"),
        'AMIS_TOKEN': sdk.get_config("token")
    }
    response = requests.get(url, headers=headers)
    print(sdk.format_json(response.json()))


def bns_helper():
    parser = argparse.ArgumentParser()
    parser.add_argument("service_name", type=str)
    args = parser.parse_args()

    url: str = sdk.get_config("url")
    url = url.format(args.service_name)
    response = requests.get(url)
    print(sdk.format_json(response.json()))


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


def timeformator():
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", type=str, default="%Y-%m-%d %H:%M:%S")
    parser.add_argument("--from-ts", action="store_true")
    parser.add_argument("time_str", type=str, nargs="?")
    args = parser.parse_args()

    if args.time_str is not None:
        time_strs = [args.time_str]
    else:
        time_strs = sys.stdin.read().strip().split('\n')

    if args.from_ts:
        for timestamp in time_strs:
            if len(str(timestamp)) == 13:
                timestamp = int(timestamp) / 1000
            elif len(str(timestamp)) == 10:
                timestamp = int(timestamp)
                pass
            else:
                raise ValueError("无效的时间戳")
            formatted_time = datetime.fromtimestamp(timestamp).strftime(args.format)
            print(formatted_time)
    else:
        for time_str in time_strs:
            time_array = time.strptime(time_str, args.format)
            timestamp = int(time.mktime(time_array))
            print(timestamp)


def pandas():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sheet_name", type=int, default=0)
    parser.add_argument("--skiprows", type=int, default=0)
    parser.add_argument("--nrows", type=int, default=None)
    parser.add_argument("--usecols", type=int, nargs='+')
    parser.add_argument("excel", type=str)
    args = parser.parse_args()
    import pandas as pd
    df = pd.read_excel(args.excel, sheet_name=args.sheet_name, skiprows=args.skiprows, nrows=args.nrows,
                       usecols=args.usecols)
    for value in df.values:
        print("\t".join(map(str, value)))


def table2markdown():
    parser = argparse.ArgumentParser()
    parser.add_argument("table", type=str, nargs="?")
    args = parser.parse_args()

    if args.table is not None:
        lines = sdk.read_file(args.table)
    else:
        lines = sys.stdin.read().splitlines()

    columns = lines[0].split('\t')
    table = '| ' + ' | '.join(['' for _ in columns]) + ' |\n'
    table += '| ' + ' | '.join(['---' for _ in columns]) + ' |\n'
    for line in lines:
        rows = line.split('\t')
        table += '| ' + ' | '.join(map(str, rows)) + ' |\n'

    print(table)


def stats_service_process():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", type=str)
    parser.add_argument("--families", type=str, nargs="*")
    parser.add_argument("-f", "--format", action="store_true")
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("stats_service_file", type=str)
    args = parser.parse_args()

    class StatsEngine:
        def __init__(self):
            self.list_operator = []

        def read(self, name, comment='', conf=None):
            if conf is not None:
                conf = json.dumps(conf)
            op = StatsEngineOperator(name, None, 'READ', conf, comment)
            self.list_operator.append(op)
            return op

        def search_tree_families(self, input_tree, families):
            output_tree = input_tree.copy()
            output_tree['child'] = []

            if 'child' in input_tree and isinstance(input_tree['child'], list) and len(input_tree['child']) > 0:
                for child in input_tree['child']:
                    node = self.search_tree_families(child, families)
                    if node is not None:
                        if 'child' in node and len(node['child']) > 0:
                            output_tree['child'].append(node)
                        elif 'conf' in node and node['conf']:
                            conf = json.loads(node['conf'])
                            if 'family' in conf:
                                output_tree['child'].append(node)

            if 'conf' in input_tree and input_tree['conf']:
                conf = json.loads(input_tree['conf'])
                if 'family' in conf and conf['family'] not in families:
                    return None
                elif 'family' in conf:
                    output_tree.pop('child', None)

            return output_tree

        def print(self, format=False, name=None, families=None):
            results = []
            for datasource in self.list_operator:
                result = json.dumps(datasource.node)
                if not name or datasource.node["name"] == name:
                    results.append(result)
            for result in results:
                if not families:
                    if format:
                        print(json.dumps(json.loads(result), indent=4, ensure_ascii=False), end="\n\n")
                    else:
                        print(json.loads(json.dumps(result)), end="\n\n")
                else:
                    tree = self.search_tree_families(json.loads(result), families)
                    if 'child' in tree and tree['child']:
                        if format:
                            print(json.dumps(tree, indent=4, ensure_ascii=False), end="\n\n")
                        else:
                            print(json.dumps(tree), end="\n\n")

    class StatsEngineOperator:
        def __init__(self, name, parent, type_, conf=None, comment='', sql='', other_operator=None):
            self.node = {
                "name": name,
                "type_": type_
            }
            if conf is not None:
                self.node["conf"] = conf
            if comment != '':
                self.node["comment"] = comment
            if sql != '' and sql is not None:
                self.node["sql"] = sql
            if other_operator is not None:
                self.node["other_operator"] = other_operator

            self.list_child = []

        def sql(self, name, sql, comment='', conf=None):
            if isinstance(sql, str):
                sql = ' '.join(sql.replace('\n', ' ').split())
            if conf is not None:
                if "product" in conf:
                    conf['__function__'] = inspect.stack()[1].function
                conf = json.dumps(conf)
            op = StatsEngineOperator(name, self, 'SQL', conf, comment, sql)
            self.list_child.append(op)
            if 'child' not in self.node:
                self.node["child"] = []
            self.node["child"].append(op.node)
            return op

    def do_process():
        is_delete = False if args.debug else True
        with tempfile.NamedTemporaryFile(delete=is_delete) as temp_file:
            contents = sdk.read_file(args.stats_service_file)
            start_line = 0
            end_line = 0
            for i in range(len(contents)):
                line = contents[i]
                if line.strip().startswith("from ") or line.strip().startswith(
                        "statsengine =") or line.strip().startswith("read_common_datasource("):
                    start_line = i + 1
                    continue
                if line.strip().startswith("def main():") or line.strip().startswith("if __name__ == '__main__'"):
                    end_line = i
                    break
            codes = contents[start_line:end_line]

            head = [
                "#!/usr/bin/env python",
                "import json",
                "import sys",
                "import inspect",
                textwrap.dedent(inspect.getsource(StatsEngine)),
                textwrap.dedent(inspect.getsource(StatsEngineOperator)),
                "statsengine = StatsEngine()"
            ]
            codes.insert(0, "\n".join(head))
            name = f"'{args.name}'" if args.name else None
            codes.append(f"statsengine.print(format={args.format}, name={name}, families={args.families})\n")
            sdk.write_file(temp_file.name, codes)
            if args.debug:
                print(temp_file.name)
            process = sdk.run_cmd([sys.executable, temp_file.name])
            print(process.stdout)

    do_process()


def stats_run_bin():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--datasource", type=str, required=True)
    parser.add_argument("--mode", type=str, choices=['xstp', 'local'], required=True)
    parser.add_argument("--log", type=str, required=True)
    parser.add_argument("--tmclient", type=str, required=True)
    parser.add_argument("--compress_type", type=int, choices=[0, 1, 2, 3], required=True,
                        help="CPRS_NONE = 0, CPRS_GZIP = 1, CPRS_ZIPPY = 2, CPRS_LZ4 = 3")
    parser.add_argument("--deserializer_class", type=str, required=True,
                        choices=["BundleDeser", "B2logDeser", "SequenceHeadFileDeser", "PlainTextDeser",
                                 "UpdaterMessageDeser"],
                        help="BundleTask = BundleDeser, "
                             "DataTaskValue{LOG_PB = B2logDeser, LOG_SEQ_FILE = SequenceHeadFileDeser, "
                             "LOG_BIN = (chunk.data_type: OLAPUpdateMessage){UpdaterMessageDeser}, "
                             "LOG_TEXT = PlainTextDeser, Other = BundleDeser}, "
                             "UpdaterOutPutMessage = UpdaterMessageDeser, "
                             "MolaPusherTask = UpdaterMessageDeser, "
                             "TaskUpdater4Backuper = UpdaterMessageDeser(data_type : OLAPUpdateMessage)")
    parser.add_argument("--conf", type=str, required=True)
    parser.add_argument("--input_file", type=str)
    parser.add_argument("bin", type=str)
    args = parser.parse_args()

    datasource = args.datasource.replace("datasource_", "")
    mode = args.mode
    log = args.log
    tmclient = args.tmclient
    conf = args.conf
    compress = args.compress_type
    deserializer = args.deserializer_class
    input_file = args.input_file
    stats_bin = args.bin

    # output, filelist, filesize
    output_path = ""
    file_list = ""
    filesize = 0
    if mode == 'local':
        if not input_file:
            raise ValueError("input_file must be set when mode is local")
        output_path = Path(input_file).absolute().parent.joinpath("output")
        if not output_path.exists():
            output_path.mkdir()
        file_list = Path(input_file).parent.joinpath("filelist")
        sdk.write_file(str(file_list), [f"{input_file} 1"])
        filesize = Path(input_file).stat().st_size

    replace_path = str(Path.home().joinpath("hdfs")) + "/"

    # conf
    bin_conf = conf.rpartition('.')[0]
    backup_bin_conf = str(Path(bin_conf)) + f".backup"
    if Path(bin_conf).exists():
        os.rename(Path(bin_conf), backup_bin_conf)
    shutil.copy(Path(conf), Path(bin_conf))
    sdk.modify_file(str(Path(bin_conf)), "/home/volume/", replace_path)

    # log, tm
    current_path = Path.cwd()
    relative_path = Path('./' + '../' * (len(Path(bin_conf).absolute().parts) - 1))
    sdk.modify_file(bin_conf, "tmclient.conf", str(relative_path) + tmclient)
    sdk.modify_file(bin_conf, "log.conf", str(relative_path) + log)

    # dict
    dict_conf = Path(bin_conf).parent.joinpath("updater_dict.conf")
    backup_dict_conf = str(Path(dict_conf)) + f".backup"
    if dict_conf.exists():
        dict_content = sdk.read_file_content(str(dict_conf))
        if "/home/volume/" in dict_content:
            shutil.copy(dict_conf, backup_dict_conf)
            sdk.modify_file(str(dict_conf), "/home/volume/", replace_path)
        pattern = rf'{replace_path}[^ \n]*'
        dict_paths = re.findall(pattern, dict_content)
        not_found_dicts = []
        for dict_path in dict_paths:
            if not Path(dict_path).exists():
                not_found_dicts.append(dict_path)
        if not_found_dicts:
            raise FileNotFoundError(f"dict {not_found_dicts} is not found")

    def consumer(process):
        while True:
            output = process.stderr.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                sys.stdout.write(output)
                sys.stdout.flush()

    try:
        cmd = [f"{stats_bin}", f"-from={mode}", f"-file={file_list}", f"-datasource={datasource}",
               f"-deserializer_class={deserializer}", f"-output_file_path={output_path}", "-bundle_offset=0",
               f"-bundle_chunk_size={filesize}", f"-compress_type_={compress}"]
        print('-' * shutil.get_terminal_size().columns)
        print(' '.join(cmd))
        print('-' * shutil.get_terminal_size().columns)
        sdk.run_popen(cmd)
    finally:
        os.remove(file_list)
        if Path(backup_bin_conf).exists():
            os.rename(backup_bin_conf, Path(bin_conf))
        else:
            os.remove(bin_conf)
        if Path(backup_dict_conf).exists():
            os.rename(backup_dict_conf, Path(dict_conf))


def bp_sub():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cluster", type=str, required=True)
    parser.add_argument("--meta_host", type=str, required=True)
    parser.add_argument("--unpack", action="store_true")
    parser.add_argument("--pipename", type=str, required=True)
    parser.add_argument("--username", type=str, required=True)
    parser.add_argument("--password", type=str, required=True)
    parser.add_argument("--pipelet_id", type=int, required=False, default=1)
    parser.add_argument("--startpoint", type=int, required=False, default=-1)
    parser.add_argument("--sub_count", type=int, required=False, default=1)
    parser.add_argument("--out_path", type=str, required=False)
    args = parser.parse_args()

    root_path = sdk.get_config("root_path")
    os.chdir(root_path)

    cluster = '/' + args.cluster if not args.cluster.startswith('/') else args.cluster
    sdk.modify_file_by_patten(str(Path("./conf/bigpipe.conf")),
                              r'(root_path:\s*)(.*)', lambda m: f"{m.group(1)}{cluster}")
    sdk.modify_file_by_patten(str(Path("./conf/bigpipe.conf")),
                              r'(meta_host:\s*)(.*)', lambda m: f"{m.group(1)}{args.meta_host}")
    pack = 'False' if args.unpack else 'True'
    sdk.modify_file_by_patten(str(Path("./conf/gflags.conf")),
                              r'(--pack=\s*)(.*)', lambda m: f"{m.group(1)}{pack}")
    sdk.modify_file_by_patten(str(Path("./conf/bp.conf")),
                              r'(pipename:\s*)(.*)', lambda m: f"{m.group(1)}{args.pipename}")
    sdk.modify_file_by_patten(str(Path("./conf/bp.conf")),
                              r'(username:\s*)(.*)', lambda m: f"{m.group(1)}{args.username}")
    sdk.modify_file_by_patten(str(Path("./conf/bp.conf")),
                              r'(password:\s*)(.*)', lambda m: f"{m.group(1)}{args.password}")
    sdk.modify_file_by_patten(str(Path("./conf/bp.conf")),
                              r'(pipelet_id:\s*)(.*)', lambda m: f"{m.group(1)}{args.pipelet_id}")
    sdk.modify_file_by_patten(str(Path("./conf/bp.conf")),
                              r'(startpoint:\s*)(.*)', lambda m: f"{m.group(1)}{args.startpoint}")
    sdk.modify_file_by_patten(str(Path("./conf/bp.conf")),
                              r'(sub_count:\s*)(.*)', lambda m: f"{m.group(1)}{args.sub_count}")

    cmd = "./bin/bp_tool"
    process = sdk.run_shell(cmd)
    print(process.stdout)

    os.rename(Path("./data/out_data"), Path(f"./data/{args.pipename}.sub"))

    if args.out_path and os.path.exists(args.out_path):
        Path(f"./data/{args.pipename}.sub").rename(f"{args.out_path}/{args.pipename}.sub")


def agent_helper():
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', type=str, required=True)
    parser.add_argument('input', type=str)
    args = parser.parse_args()

    db = args.db
    pre_cmd: str = sdk.get_config("pre_cmd")
    sqls: dict[str, str] = sdk.get_config("sqls")

    app_info_cmd = sqls['app_info'].format(db, args.input)
    print(app_info_cmd)
    process = sdk.run_shell(pre_cmd + app_info_cmd)
    print(process.stdout)
    user_info_id_match = re.search(r"user_info_id:\s*(\d+)", process.stdout)
    user_info_id = user_info_id_match.group(1) if user_info_id_match else None

    app_package_cmd = sqls['app_package'].format(db, sdk.crc32(args.input) % 16, args.input)
    print(app_package_cmd)
    process = sdk.run_shell(pre_cmd + app_package_cmd)
    print(process.stdout)

    if user_info_id:
        business_detail_cmd = sqls['business_detail'].format(db, (int(user_info_id)) % 16, args.input)
        print(business_detail_cmd)
        process = sdk.run_shell(pre_cmd + business_detail_cmd)
        print(process.stdout)


def rcc_helper():
    parser = argparse.ArgumentParser()
    parser.add_argument('--from_env', type=str, required=True)
    parser.add_argument('--to_env', type=str, required=True)
    parser.add_argument('project', type=str)
    args = parser.parse_args()

    def rcc(token, environment, environment_url, version_url, group_url, item_url):
        environment_url = environment_url.format(token=token, environment=environment)
        response = requests.get(environment_url).json()
        if response['status'] != 0:
            raise RuntimeError(f"{environment}: get environment failed: {response['msg']}")
        environmentId = response['data']['environmentId']

        version_url = version_url.format(token=token, environmentId=environmentId)
        response = requests.get(version_url).json()
        if response['status'] != 0:
            raise RuntimeError(f"{environment}: get version failed: {response['msg']}")
        versionId = response['data']['versionId']

        group_url = group_url.format(token=token, versionId=versionId)
        response = requests.get(group_url).json()
        if response['status'] != 0:
            raise RuntimeError(f"get group {versionId} failed: {response['msg']}")
        groups = response['data']
        group_map = {}
        for group in groups:
            group_map[group['groupId']] = group['groupName']

        item_url = item_url.format(token=token)
        item_body = {"versionId": versionId}
        response = requests.post(item_url, json=item_body).json()
        if response['status'] != 0:
            raise RuntimeError(f"{environment}: get config item failed: {response['msg']}")
        item_map = {}
        for item in response['data']:
            item_map[item['key']] = item

        return group_map, item_map

    project_config: dict = sdk.get_config(args.project)
    auth_url = sdk.get_config("auth_url")
    auth_body = {"projectName": project_config['projectName'], "apiPassword": project_config['apiPassword']}
    result = requests.post(auth_url, json=auth_body).json()
    if result['status'] != 0:
        raise RuntimeError(f"get auth failed: {result['msg']}")
    tk = result['data']['token']
    new_group_map, news_map = rcc(tk, args.from_env, sdk.get_config('environment_url'), sdk.get_config('version_url'),
                                  sdk.get_config('group_url'), sdk.get_config('item_url'))
    old_group_map, olds_map = rcc(tk, args.to_env, sdk.get_config('environment_url'), sdk.get_config('version_url'),
                                  sdk.get_config('group_url'), sdk.get_config('item_url'))
    diff_keys = set(news_map.keys()) - set(olds_map.keys())

    group_kv_map = {}
    for diff_key in diff_keys:
        item = news_map[diff_key]
        groupId = item['groupId']
        groupName = new_group_map[groupId]
        kvs = group_kv_map.get(groupName, {})
        kvs[item['key']] = item['value']
        group_kv_map[groupName] = kvs

    for group_name, item in group_kv_map.items():
        if group_name not in old_group_map.values():
            group_kv_map[group_name] = "new group"

    print(json.dumps(group_kv_map))


@runtime(RuntimeEnv.NONE)
def funcs() -> dict:
    funcs_map = {}

    for name, item in globals().items():
        if not (inspect.isfunction(item) and item.__module__ == __name__):
            continue

        env = getattr(item, RuntimeKey.ENV.value, RuntimeEnv.PYTHON.value)
        if env == RuntimeEnv.NONE.value:
            continue

        functions = [] if env not in funcs_map else funcs_map[env]
        info = {"name": name, "item": item}
        functions.append(info)

        funcs_map[env] = functions

    return funcs_map


@runtime(RuntimeEnv.NONE)
def main():
    os.environ[RuntimeKey.MODE.value] = RuntimeMode.PRODUCT.value
    sys.excepthook = sdk.handle_exception_hook

    if os.path.basename(os.path.realpath(__file__)) == os.path.basename(sys.argv[0]):
        del sys.argv[0]

    func_name = os.path.basename(sys.argv[0])

    if func_name not in globals():
        raise RuntimeError(f"Unknown command: {func_name}")

    globals()[func_name]()


if __name__ == "__main__":
    main()
