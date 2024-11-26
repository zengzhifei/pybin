#!/usr/bin/env sh

scd() {
    result=$(cli.py "scd" "$@")

    if [ $? -eq 250 ]; then
        # shellcheck disable=SC2164
        cd "$result"
    elif [ -n "$result" ]; then
        # shellcheck disable=SC2039
        echo -e "$result"
    fi
}

gomysql() {
    result=$(cli.py "gomysql" "$@")

    if [ $? -eq 250 ]; then
        eval "$result"
    elif [ -n "$result" ]; then
        # shellcheck disable=SC2039
        echo -e "$result"
    fi
}

goredis() {
    result=$(cli.py "goredis" "$@")

    if [ $? -eq 250 ]; then
        eval "$result"
    elif [ -n "$result" ]; then
        # shellcheck disable=SC2039
        echo -e "$result"
    fi
}

gomachine() {
    result=$(cli.py "gomachine" "$@")

    if [ $? -eq 250 ]; then
        eval "$result"
    elif [ -n "$result" ]; then
        # shellcheck disable=SC2039
        echo -e "$result"
    fi
}

goinstance() {
    result=$(cli.py "goinstance" "$@")

    if [ $? -eq 250 ]; then
        eval "$result"
    elif [ -n "$result" ]; then
        # shellcheck disable=SC2039
        echo -e "$result"
    fi
}


