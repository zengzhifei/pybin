#!/usr/bin/env python3
import argparse
import ast
import hashlib
import importlib
import inspect
import ipaddress
import json
import logging
import os
import re
import shutil
import smtplib
import socket
import subprocess
import sys
import threading
import traceback
import unicodedata
import zlib
from datetime import datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from subprocess import Popen
from typing import Type, AnyStr, List, Any, Dict, Optional, Callable, Tuple

import psutil
import requests
import setproctitle as setproctitle
from colorama import Fore, Style
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from moz_sql_parser import parse
from requests import Response
from requests.auth import HTTPBasicAuth

try:
    from .ann import RuntimeKey, RuntimeMode, RuntimeEnv
except ImportError:
    from ann import RuntimeKey, RuntimeMode, RuntimeEnv


def handle_exception_hook(ex: Type, value: str, trace):
    run_mode = os.getenv(RuntimeKey.MODE.value)
    if run_mode is not None and run_mode.lower() == RuntimeMode.DEBUG.value:
        traceback.print_exception(ex, value, trace)
    else:
        print(f"{ex.__name__}: {value}")


def get_home() -> Path:
    return Path.home()


def get_ip() -> str:
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)


def get_sh_env() -> str:
    return os.getenv("SHELL").split("/")[-1]


def get_sh_profiles() -> list:
    configs = []
    env = get_sh_env()
    home = Path.home()
    if env == "zsh":
        if os.path.exists(home.joinpath(".zshrc")):
            configs.append(home.joinpath(".zshrc"))
        if os.path.exists(home.joinpath(".zprofile")):
            configs.append(home.joinpath(".zprofile"))
        if len(configs) == 0:
            configs.append(home.joinpath(".zshrc"))
    else:
        if os.path.exists(home.joinpath(".bashrc")):
            configs.append(home.joinpath(".bashrc"))
        if os.path.exists(home.joinpath(".bash_profile")):
            configs.append(home.joinpath(".bash_profile"))
        if len(configs) == 0:
            configs.append(home.joinpath(".bashrc"))
    return configs


def read_file(filepath: str, line_count: int = None, line_num: bool = None) -> List[str]:
    contents = []
    line_number = 0
    with open(filepath, 'r', encoding='utf-8') as file:
        for line in file:
            line_number += 1
            if line_num is not None and line_num is True:
                contents.append(f"{line_number}\t{line}")
            else:
                contents.append(line)
            if line_count is not None and len(contents) >= line_count:
                break

    return contents


def read_file_content(filepath: str) -> str:
    with open(filepath, 'r', encoding='utf-8') as file:
        return file.read()


def read_json_file(filepath: str) -> Dict:
    with open(filepath, 'r', encoding='utf-8') as file:
        data = json.load(file)
    return data


def write_file(filepath: str, lines: List[AnyStr]):
    with open(filepath, 'w', encoding='utf-8') as file:
        file.writelines(lines)


def write_file_content(filepath: str, data: str):
    with open(filepath, 'w', encoding='utf-8') as file:
        file.write(data)


def write_file_content_by_append(filepath: str, data: str):
    with open(filepath, 'a', encoding='utf-8') as file:
        file.write(data)


def write_json_file(filepath: str, data: dict):
    with open(filepath, 'w', encoding='utf-8') as file:
        json.dump(data, file, indent=4)


def modify_file(filepath: str, old_text: str, new_text: str):
    with open(filepath, 'r') as file:
        content = file.read()
    content = content.replace(old_text, new_text)
    with open(filepath, 'w') as file:
        file.write(content)


def modify_file_by_patten(filepath: str, pattern: str, replace: Callable[[str], str]):
    with open(filepath, 'r') as file:
        lines = file.readlines()

    with open(filepath, 'w') as file:
        for line in lines:
            line = re.sub(pattern, replace, line)
            file.write(line)


def upload_file(url: str, file_path: str) -> Response:
    with open(file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post(url, files=files)
    return response


def upload_file_with_curl(url: str, file_path: str) -> AnyStr:
    curl_command = ['curl', '-F', f'file=@{file_path}', url]

    def consumer(process):
        line = 0
        while True:
            output = process.stderr.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                line += 1
                if line >= 3:
                    sys.stdout.write('\r' + output.strip())
                    sys.stdout.flush()
                else:
                    sys.stdout.write(output)
                    sys.stdout.flush()

    return run_popen(curl_command, consumer=consumer)


def get_config(key: str, is_caller: bool = True, config_file: str = None, default_value: Any = None) -> Any:
    if config_file is None:
        runtime_path = os.environ.get("PYBIN_RUNTIME_PATH")
        config_file = os.path.join(runtime_path, "config.json")

    if not os.path.exists(config_file):
        raise FileNotFoundError(f"{config_file} is not found")

    config = read_json_file(config_file)

    if is_caller:
        stack = inspect.stack()
        caller_frame = stack[1]
        caller_name = caller_frame.function
        item: Dict = config.get(caller_name)
        if item is None:
            if default_value is not None:
                return default_value
            else:
                raise KeyError(f"{caller_name} not configured")
    else:
        item = config

    value = item.get(key)
    if value is None:
        if default_value is not None:
            return default_value
        else:
            raise KeyError(f"{key} not configured")

    return value


def merge_two_levels_dict(dict1: dict, dict2: dict) -> None:
    for key, value in dict2.items():
        if isinstance(value, dict) and key in dict1 and isinstance(dict1[key], dict):
            dict1[key].update(value)
        else:
            dict1[key] = value


def trim(text: AnyStr, position: int = 0) -> AnyStr:
    lines = text.splitlines()
    contents = []

    if position == 1:
        valid = False
        for line in lines:
            if not line.strip() and valid is False:
                continue
            else:
                contents.append(line)
                valid = True
        return "\n".join(contents)

    if position == 2:
        valid = False
        for line in reversed(lines):
            if not line.strip() and valid is False:
                continue
            else:
                contents.append(line)
                valid = True
        return "\n".join(reversed(contents))

    if position == 3:
        for line in lines:
            contents.append(line.lstrip())
        return "\n".join(contents)

    if position == 4:
        for line in lines:
            contents.append(line.rstrip())
        return "\n".join(contents)

    for line in lines:
        if not line.strip():
            continue
        else:
            contents.append(line.strip())
    return "\n".join(contents)


def remove_path_prefix_part(path: str, layers_to_remove: int) -> str:
    parts = path.strip('/').split('/')
    if len(parts) > layers_to_remove:
        return '/' + '/'.join(parts[layers_to_remove:])
    return path


def is_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def parse_bns(bns: str) -> List[dict]:
    process = run_cmd(['get_instance_by_service', '-a', bns])
    if process.stdout is None or not process.stdout:
        raise RuntimeError(f"{bns} get_instance_by_service fail, maybe is invalid")

    services = process.stdout.split("\n")

    results = []
    for service in services:
        if not service:
            continue

        cols = service.split(' ')

        tags = cols[7]
        tags_map = dict(pair.split(':', 1) for pair in tags.split(','))

        tags_map['machine'] = cols[0]
        tags_map['ip'] = cols[1]
        tags_map['group'] = cols[2]
        tags_map['port'] = cols[3]
        tags_map['instance'] = '.'.join(cols[8].split('.', 4)[:4])
        tags_map['namespace'] = cols[9]
        tags_map['workspace'] = cols[10]

        results.append(tags_map)

    if len(results) == 0:
        raise RuntimeError(f"{bns} no instance, maybe is invalid")

    return results


def java_version() -> int:
    result = run_cmd(['java', '-version'])
    version_info = result.stderr.strip()
    major_version_match = re.search(r'version "(\d+)\.', version_info, re.IGNORECASE)
    return int(major_version_match.group(1))


def concurrent_execute(tasks: List[Any], handler: Callable[[threading.Lock, Any], None], concurrent: int = 20):
    lock = threading.Lock()

    def thread_worker(chunk_tasks: List[Any]):
        for task in chunk_tasks:
            handler(lock, task)

    threads = []
    total_tasks_num = len(tasks)
    max_threads = 1024
    threads_num = min(concurrent, max_threads)
    threads_num = 1 if threads_num <= 0 else threads_num

    chunk_size = total_tasks_num // threads_num
    remainder = total_tasks_num % threads_num

    start_index = 0
    for i in range(threads_num):
        end_index = start_index + chunk_size + (1 if i < remainder else 0)
        tasks_chunk = tasks[start_index:end_index]
        start_index = end_index

        thread = threading.Thread(target=thread_worker, args=(tasks_chunk,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()


def find_available_port(start_port: int, end_port: int) -> int:
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('localhost', port))
                s.listen(1)
                return port
            except OSError:
                continue
    raise OSError(f"not find available port in range {start_port} - {end_port}")


def run_shell(cmd: str) -> subprocess.CompletedProcess:
    process = subprocess.run(cmd, shell=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True)
    if process.returncode != 0:
        raise RuntimeError(process.stderr)
    else:
        return process


def run_cmd(cmd: List[str]) -> subprocess.CompletedProcess:
    process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if process.returncode != 0:
        raise RuntimeError(process.stderr)
    else:
        return process


def run_popen(cmd: List[str], consumer: Callable[[Popen], None] = None) -> AnyStr:
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    try:
        if consumer is not None:
            consumer(process)
        else:
            while True:
                output = process.stderr.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    sys.stdout.write(output)
                    sys.stdout.flush()
    except KeyboardInterrupt:
        process.terminate()

    stdout, stderr = process.communicate()
    if process.returncode != 0:
        raise RuntimeError(stderr)
    else:
        return stdout


def align_columns(input_text: str) -> str:
    process = subprocess.run(['column', '-t'], input=input_text, capture_output=True, text=True)
    if process.returncode != 0:
        raise RuntimeError(process.stderr)
    else:
        return process.stdout


def iterate_process(condition: Callable[[str], bool], callback: Callable[[str, psutil.Process], None]) -> None:
    uid = os.getuid()
    current_pid = os.getpid()
    for proc in psutil.process_iter([]):
        try:
            if proc.pid == current_pid or uid != proc.uids().real or proc.info['cmdline'] is None:
                continue
            process_name = " ".join(proc.info['cmdline']).strip()
            proc_name = process_name.lower()
            if not condition(proc_name):
                continue
            callback(process_name, proc)
        except Exception:
            pass


def get_process_listen_ports(pid: int) -> List[int]:
    cmd = f"lsof -nP -i TCP | grep {pid} | grep -i listen | awk '{{print $9}}' | awk -F':' '{{print $2}}'"
    process = run_shell(cmd)
    return [int(item) for item in process.stdout.split("\n") if item]


def get_logging(filename: str, level: int = logging.INFO) -> logging:
    logging.basicConfig(filename=filename, filemode='a', level=level,
                        format='%(asctime)s  %(levelname)s    [%(threadName)s]   '
                               '%(funcName)s (%(module)s:%(lineno)d) '
                               ' - %(message)s')
    return logging.getLogger()


def format_json(json_data: dict) -> str:
    return json.dumps(json_data, indent=4, ensure_ascii=False)


def format_timestamp(timestamp: int = None, fmt: str = '%Y-%m-%d %H:%M:%S') -> str:
    if timestamp is None:
        dt = datetime.now()
    else:
        if timestamp > 1e12:
            dt = datetime.fromtimestamp(timestamp / 1000)
        else:
            dt = datetime.fromtimestamp(timestamp)
    return dt.strftime(fmt)


def to_timestamp(datetime_str: str, ms: bool = False) -> int:
    formats = [
        "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M",
        "%Y-%m-%d", "%Y/%m/%d", "%Y%m%d%H%M%S", "%Y%m%d"
    ]

    dt = None
    for fmt in formats:
        try:
            dt = datetime.strptime(datetime_str, fmt)
            break
        except ValueError:
            continue

    if dt is None:
        raise ValueError("the date format cannot be parsed")

    return int(dt.timestamp() * 1000) if ms else int(dt.timestamp())


def send_email(smtp_server: str, smtp_port: int, smtp_user: str, smtp_password: str, to_emails: list,
               subject: str, body: str, from_name: str = None, cc_emails: list = None, attachments: list = None,
               is_html: bool = False, use_ssl: bool = True) -> None:
    from_email = smtp_user
    cc_emails = cc_emails or []
    attachments = attachments or []

    msg = MIMEMultipart()
    msg['From'] = formataddr((from_name, from_email)) if from_name else from_email
    msg['To'] = ', '.join(to_emails)
    msg['Cc'] = ', '.join(cc_emails)
    msg['Subject'] = subject

    if is_html:
        msg.attach(MIMEText(body, 'html', 'utf-8'))
    else:
        msg.attach(MIMEText(body, 'plain', 'utf-8'))

    for file_path in attachments:
        with open(file_path, 'rb') as f:
            part = MIMEApplication(f.read())
            part.add_header('Content-Disposition', 'attachment', filename=file_path.split('/')[-1])
            msg.attach(part)

    if use_ssl:
        server = smtplib.SMTP_SSL(smtp_server, smtp_port)
    else:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
    server.login(smtp_user, smtp_password)
    server.sendmail(from_email, to_emails + cc_emails, msg.as_string())
    server.quit()


def aes_encrypt(content: bytes, key: str) -> bytes:
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(hashlib.sha256(key.encode()).digest()), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(content) + encryptor.finalize()
    return nonce + encryptor.tag + ciphertext


def aes_decrypt(data: bytes, key: str) -> bytes:
    nonce = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    cipher = Cipher(algorithms.AES(hashlib.sha256(key.encode()).digest()), modes.GCM(nonce, tag),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def crc32(key: str) -> int:
    crc_value = zlib.crc32(key.encode())
    crc_value &= 0xffffffff
    return crc_value


def get_file_md5(file_path: str) -> str:
    hash_md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def basic_auth(username: str, password: str) -> str:
    return requests.auth._basic_auth_str(username, password)


def get_display_width(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in ('F', 'W') else 1 for c in text)


def beautify_separator_line(separator: str = '-', color: str = Fore.CYAN, text: str = None,
                            text_color: str = Fore.CYAN) -> str:
    columns = shutil.get_terminal_size().columns

    if text:
        text = f' {text} '
        separator_length = max(columns - get_display_width(text), 0)
        left_separator_length = separator_length // 2
        right_separator_length = separator_length - left_separator_length
        line = (color + Style.NORMAL + left_separator_length * separator
                + text_color + Style.NORMAL + text
                + color + Style.NORMAL + right_separator_length * separator)
    else:
        line = color + Style.NORMAL + separator * columns
    return color + Style.NORMAL + line + Style.RESET_ALL


def get_multiline_input(tip: str = '', end_input_number: int = 1) -> str:
    if tip:
        print(tip, '\n')

    lines = []
    enter_count = 0

    while True:
        line = input()
        if line == "":
            enter_count += 1
            if enter_count == end_input_number:
                break
        else:
            enter_count = 0
            lines.append(line)

    return '\n'.join(lines)


def get_module_funcs(py_path: str) -> dict:
    funcs_map = {}

    module_name = os.path.splitext(os.path.basename(py_path))[0]
    spec = importlib.util.spec_from_file_location(module_name, py_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    for name, item in module.__dict__.items():
        if not (inspect.isfunction(item) and item.__module__ == module_name):
            continue

        env = getattr(item, RuntimeKey.ENV.value, RuntimeEnv.PYTHON.value)
        if env == RuntimeEnv.NONE.value:
            continue

        functions = {} if env not in funcs_map else funcs_map[env]
        functions[name] = item

        funcs_map[env] = functions

    return funcs_map


def get_path_parent_by_level(path: str, level: int) -> Tuple[Optional[str], Optional[str]]:
    p = Path(path)
    for _ in range(level):
        p = p.parent
        if p == p.parent:
            return None, None
    return str(p), p.name


def run_main(runtime_mode: RuntimeMode = RuntimeMode.PRODUCT) -> None:
    if RuntimeKey.MODE.value not in os.environ:
        os.environ[RuntimeKey.MODE.value] = runtime_mode.value

    sys.excepthook = handle_exception_hook

    stack = inspect.stack()
    caller = stack[1]
    cli = os.path.realpath(caller.filename)

    if os.path.basename(os.path.realpath(cli)) == os.path.basename(sys.argv[0]):
        del sys.argv[0]

    if len(sys.argv) <= 0:
        raise RuntimeError("Missing command entry parameters")

    func_name = os.path.basename(sys.argv[0])

    funcs_map = {k: v for functions in get_module_funcs(cli).values() for k, v in functions.items()}
    if func_name not in funcs_map:
        raise RuntimeError(f"Unknown command: {func_name}")

    funcs_map[func_name]()


class ArgParseType:
    @staticmethod
    def number(value: str):
        value = value.strip()
        try:
            val = ast.literal_eval(value)
            if isinstance(val, (int, float)):
                return val
            raise ValueError
        except Exception:
            raise argparse.ArgumentTypeError(f"invalid number value: {value!r}")


class HttpServer:
    def __init__(self, port: int = 8000, name: str = None):
        self.port = port
        self.name = name.strip()
        self.request_handler_class = None
        self.use_threading = False
        self.get_method = None
        self.post_method = None

    def set_get_method(self, method: Optional[Callable[[BaseHTTPRequestHandler], None]] = None):
        self.get_method = method

    def set_post_method(self, method: Optional[Callable[[BaseHTTPRequestHandler], None]] = None):
        self.post_method = method

    def set_request_handler_class(self,
                                  request_handler_class: Callable[[Any, Any, HTTPServer], BaseHTTPRequestHandler]):
        self.request_handler_class = request_handler_class

    def use_threading_http_server(self, use_threading: bool = True):
        self.use_threading = use_threading

    def _run(self):
        if self.name is not None:
            setproctitle.setproctitle(self.name)

        if self.request_handler_class is not None:
            request_handler_class = self.request_handler_class
        else:
            request_handler_class = self._make_request_handler_class()

        if self.use_threading:
            httpd = ThreadingHTTPServer(server_address=('', self.port), RequestHandlerClass=request_handler_class)
        else:
            httpd = HTTPServer(server_address=('', self.port), RequestHandlerClass=request_handler_class)

        host, port = httpd.socket.getsockname()[:2]
        print(f"Serving HTTP on {host} port {port}.")

        httpd.serve_forever()

    def start(self, daemon: bool = False):
        if daemon:
            pid = os.fork()
            if pid == 0:
                self._run()
            else:
                sys.exit(0)
        else:
            self._run()

    def _make_request_handler_class(self) -> Callable[[Any, Any, HTTPServer], BaseHTTPRequestHandler]:
        class RequestHandler(BaseHTTPRequestHandler):
            http_server: Optional[HttpServer]

            def log_message(self, format, *args):
                pass

            def do_GET(self):
                if self.http_server.get_method is not None:
                    try:
                        self.http_server.get_method(self)
                    except Exception as e:
                        self.error(f"{e}")

            def do_POST(self):
                if self.http_server.post_method is not None:
                    try:
                        self.http_server.post_method(self)
                    except Exception as e:
                        self.error(f"{e}")

            def ok(self, response: str):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(response.encode("utf-8"))

            def error(self, response: str):
                self.send_response(500)
                self.end_headers()
                self.wfile.write(response.encode("utf-8"))

        RequestHandler.http_server = self
        return RequestHandler


class Sql2EsConverter:
    def __init__(self, sql: str):
        self.__index = None
        self.__sql = sql
        self.__parsed = parse(sql)
        self.__dsl = {}

    def get_dsl(self, indent: int = 2) -> str:
        return json.dumps(self.__dsl, indent=indent)

    def get_index(self) -> str:
        return self.__index

    def convert(self) -> 'Sql2EsConverter':
        self.__dsl = {}

        if 'select' in self.__parsed:
            self.__dsl['_source'] = self.__parse_select(self.__parsed['select'])

        if 'from' in self.__parsed:
            self.__index = self.__parsed['from']

        if 'where' in self.__parsed:
            self.__dsl['query'] = self.__parse_where(self.__parsed['where'])

        if 'orderby' in self.__parsed:
            self.__dsl['sort'] = self.__parse_order_by(self.__parsed['orderby'])

        if 'limit' in self.__parsed and 'size' not in self.__dsl:
            self.__dsl['size'] = self.__parsed['limit']

        return self

    def __parse_select(self, select) -> list:
        fields = []
        if isinstance(select, list):
            for item in select:
                value = item.get('value')
                if isinstance(value, str):
                    fields.append(value)
        elif isinstance(select, dict):
            value = select.get('value')
            if isinstance(value, str):
                fields.append(value)
            elif isinstance(value, dict):
                if 'count' in value:
                    self.__dsl['size'] = 0
        return fields

    def __parse_order_by(self, order) -> list:
        if isinstance(order, dict):
            return [{order['value']: {'order': order.get('sort', 'asc')}}]
        else:
            return [{o['value']: {'order': o.get('sort', 'asc')}} for o in order]

    def __parse_where(self, where) -> dict:
        return self.__parse_where_logic(where)

    def __parse_where_logic(self, expr) -> dict:
        if isinstance(expr, str):
            # 支持 NOT is_admin => { "term": { "is_admin": true } }
            return {'term': {expr: True}}

        if isinstance(expr, dict):
            if 'and' in expr:
                must_dsl = {'bool': {'must': [self.__parse_where_logic(e) for e in expr['and']]}}
                return self.__parse_where_after(must_dsl, 'must')
            elif 'or' in expr:
                should_dsl = {'bool': {'should': [self.__parse_where_logic(e) for e in expr['or']]}}
                return self.__parse_where_after(should_dsl, 'should')
            elif 'not' in expr:
                must_not_dsl = {'bool': {'must_not': [self.__parse_where_logic(expr['not'])]}}
                return self.__parse_where_after(must_not_dsl, 'must_not')

            # 通用比较操作符
            ops = {
                ('=', '==', 'eq'): lambda f, v: {'term': {f: v}},
                ('!=', '<>', 'neq'): lambda f, v: {'bool': {'must_not': [{'term': {f: v}}]}},
                ('>', 'gt'): lambda f, v: {'range': {f: {'gt': v}}},
                ('<', 'lt'): lambda f, v: {'range': {f: {'lt': v}}},
                ('>=', 'gte'): lambda f, v: {'range': {f: {'gte': v}}},
                ('<=', 'lte'): lambda f, v: {'range': {f: {'lte': v}}},
                ('in',): lambda f, v: {'terms': {f: [v] if not isinstance(v, list) else v}},
                ('nin',): lambda f, v: {'bool': {'must_not': [{'terms': {f: [v] if not isinstance(v, list) else v}}]}},
                ('like',): lambda f, v: {'wildcard': {f: re.sub(r'^%|%$', '*', v)}}
            }

            for op_tuple, handler in ops.items():
                op_tuple = op_tuple if isinstance(op_tuple, tuple) else (op_tuple,)
                op = next(iter(expr))

                if op not in op_tuple:
                    continue

                field, value = expr[op]
                field = field.replace('\\', '')
                if isinstance(value, dict) and 'literal' in value:
                    value = value['literal']

                query_clause = handler(field, value)

                if '.' in field:
                    nested_path = field.split('.')[0]
                    return {'nested': {'path': nested_path, 'query': query_clause}}
                else:
                    return query_clause

        raise ValueError("Unsupported expression: " + str(expr))

    def __parse_where_after(self, dsl, clause) -> str:
        clause_list = dsl['bool'][clause]
        nested_dict_list = {}
        for clause_item in reversed(clause_list):
            if 'nested' in clause_item:
                nested_list = nested_dict_list.get(clause_item['nested']['path'], [])
                nested_list.append(clause_item['nested']['query'])
                nested_dict_list[clause_item['nested']['path']] = nested_list
                clause_list.remove(clause_item)

        for key, values in nested_dict_list.items():
            dsl['bool'][clause].append({'nested': {'path': key, 'query': {'bool': {clause: values}}}})

        return dsl
