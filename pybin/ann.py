from enum import Enum


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
