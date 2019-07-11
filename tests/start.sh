#!/bin/sh
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
else
    if [ "${1}x" = "basex" ]; then
        glob="\
        swoole_atomic \
        swoole_event \
        swoole_function \
        swoole_global \
        swoole_process \
        swoole_process_pool \
        swoole_table \
        \
        swoole_coroutine* \
        swoole_channel_coro \
        swoole_client_coro \
        swoole_http_client_coro \
        swoole_http2_client_coro \
        swoole_server \
        swoole_http_server \
        swoole_websocket_server \
        swoole_redis_server \
        swoole_mysql_coro \
        swoole_redis_coro \
        swoole_socket_coro \
        swoole_runtime"
        if [ ${#} -gt 1 ]; then
            args="${@}"
            args="${args#* }"
            glob="${args} ${glob}"
        fi
    else
        glob="$@"
    fi
fi

if [ $? -eq 0 ]; then
    PHPT=1 ${TEST_PHP_EXECUTABLE} -d "memory_limit=1024m" ${__DIR__}/run-tests ${glob}
fi

# after tests
clear_php
rm -f /tmp/swoole.log > /dev/null 2>&1
