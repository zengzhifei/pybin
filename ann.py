#!/usr/bin/env python3
import time
from enum import Enum
from functools import wraps


class RuntimeMode(Enum):
    DEBUG = "debug"
    PRODUCT = "product"


class RuntimeEnv(Enum):
    PYTHON = "python"
    SHELL = "shell"
    NONE = "none"


class RuntimeKey(Enum):
    MODE = "_runtime_mode"
    ENV = "_runtime_env"
    EXIT_CODE = "_runtime_exit_code"


def runtime(env: RuntimeEnv = RuntimeEnv.PYTHON, shell_exit_code: int = 0):
    def wrapper(func):
        setattr(func, RuntimeKey.ENV.value, env.value)
        if env == RuntimeEnv.SHELL:
            setattr(func, RuntimeKey.EXIT_CODE.value, shell_exit_code)
        return func

    return wrapper


def time_cost(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"time cost: {func.__name__} {elapsed_time:.4f} seconds")
        return result

    return wrapper
