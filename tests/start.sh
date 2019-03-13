#!/usr/bin/env bash
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

clear_php()
{
  ps -A | grep \.php$ | grep -v phpstorm | grep -v php-fpm | awk '{print $1}' | xargs kill -9 > /dev/null 2>&1
}

## before tests
clear_php
if [ `ulimit -n` -le 16384 ]; then
    ulimit -n 16384 > /dev/null 2>&1
fi

# run tests
if [ -z "${TEST_PHP_EXECUTABLE}" ]; then
    export TEST_PHP_EXECUTABLE=`which php`
fi
if [ -z "${1}" ]; then
    glob="swoole_*"
elif [ "${1}"x == "base"x ]; then
    _args=("$@")
    unset _args["0"]
    _args_str=""
    for i in ${_args[@]};
    do
        _args_str="${_args_str} ${i}"
    done
    glob="${_args_str}
    swoole_atomic \
    swoole_buffer \
    swoole_event \
    swoole_function \
    swoole_global \
    swoole_lock \
    swoole_process \
    swoole_process_pool \
    swoole_table \
    \
    swoole_coroutine \
    swoole_coroutine_util \
    swoole_channel_coro \
    swoole_client_coro \
    swoole_http_client_coro \
    swoole_http2_client_coro \
    swoole_server \
    swoole_http_server \
    swoole_mysql_coro \
    swoole_redis_coro \
    swoole_redis_server \
    swoole_socket_coro \
    swoole_runtime"
else
    glob="$@"
fi

PHPT=1 ${TEST_PHP_EXECUTABLE} -d "memory_limit=1024m" ${__DIR__}/run-tests ${glob}

# after tests
clear_php
rm -f /tmp/swoole.log > /dev/null 2>&1
