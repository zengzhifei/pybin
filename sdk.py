#!/usr/bin/env python3
import hashlib
import inspect
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import sys
import threading
import traceback
import zlib
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from subprocess import Popen
from typing import Type, AnyStr, List, Any, Dict, Optional, Callable

import psutil
import requests
import setproctitle as setproctitle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from requests import Response

from ann import RuntimeKey, RuntimeMode


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


def get_config(key: str, is_caller: bool = True, config_file: str = None) -> Any:
    if config_file is None:
        current_dir = os.path.dirname(os.path.realpath(__file__))
        config_file = os.path.join(current_dir, "config.json")

    if not os.path.exists(config_file):
        raise FileNotFoundError(f"{config_file} is not found")

    config = read_json_file(config_file)

    if is_caller:
        stack = inspect.stack()
        caller_frame = stack[1]
        caller_name = caller_frame.function
        item: Dict = config.get(caller_name)
        if item is None:
            raise KeyError(f"{caller_name} not configured")
    else:
        item = config

    value = item.get(key)
    if value is None:
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

        cols = service.split()

        tags = cols[7]
        tags_map = dict(pair.split(':', 1) for pair in tags.split(','))

        tags_map['machine'] = cols[0]
        tags_map['ip'] = cols[1]
        tags_map['group'] = cols[2]
        tags_map['port'] = cols[3]
        tags_map['instance'] = '.'.join(cols[8].split('.', 4)[:4])
        tags_map['workspace'] = cols[9]

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
    process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
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


class HttpServer:
    def __init__(self, port: int = 8000, name: str = None):
        self.port = port
        self.name = name.strip()
        self.request_handler_class = None
        self.useThreadingHTTPServer = False
        self.get_method = None
        self.post_method = None

    def set_get_method(self, method: Optional[Callable[[BaseHTTPRequestHandler], None]] = None):
        self.get_method = method

    def set_post_method(self, method: Optional[Callable[[BaseHTTPRequestHandler], None]] = None):
        self.post_method = method

    def set_request_handler_class(self,
                                  request_handler_class: Callable[[Any, Any, HTTPServer], BaseHTTPRequestHandler]):
        self.request_handler_class = request_handler_class

    def use_threading_http_server(self, useThreadingHTTPServer: bool = True):
        self.useThreadingHTTPServer = useThreadingHTTPServer

    def _run(self):
        if self.name is not None:
            setproctitle.setproctitle(self.name)

        if self.request_handler_class is not None:
            RequestHandlerClass = self.request_handler_class
        else:
            RequestHandlerClass = self._make_request_handler_class()

        if self.useThreadingHTTPServer:
            httpd = ThreadingHTTPServer(server_address=('', self.port), RequestHandlerClass=RequestHandlerClass)
        else:
            httpd = HTTPServer(server_address=('', self.port), RequestHandlerClass=RequestHandlerClass)

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
                return

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

        def request_handler_factory(*args, **kwargs):
            handler = RequestHandler(*args, **kwargs)
            handler.http_server = self
            return handler

        return request_handler_factory
