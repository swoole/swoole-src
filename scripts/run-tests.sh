#!/bin/sh -e
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

[ -z "${SWOOLE_BRANCH}" ] && export SWOOLE_BRANCH="master"

#-------------PHPT-------------
cd ${__DIR__} && cd ../tests/

# initialization
echo "" && echo "⭐️ Initialization for tests..." && echo ""

if [ "$SWOOLE_CI_IN_MACOS" = 1 ]; then
  echo "run in macOS, skip init database"
else
  php ./init
fi

cd ./include/lib
echo "composer update"
composer update
cd -
echo ""

# debug
for debug_file in ${__DIR__}/debug/*.php
do
    if test -f "${debug_file}";then
        debug_file_basename="`basename ${debug_file}`"
        echo "" && echo "====== RUN ${debug_file_basename} ======" && echo ""
        php "${debug_file}"
        echo "" && echo "========================================" && echo ""
    fi
done

# run tests @params($1=list_file, $2=options)
run_tests(){
    ./start.sh \
    "`tr '\n' ' ' < ${1} | xargs`" \
    -w ${1} \
    ${2}
}

has_failures(){
    cat tests.list
}

should_exit_with_error(){
    if [ "${SWOOLE_BRANCH}" = "valgrind" ]; then
        set +e
        find ./ -type f -name "*.mem"
        set -e
    else
        has_failures
    fi
}

touch tests.list
trap "rm -f tests.list; echo ''; echo '⌛ Done on '`date "+%Y-%m-%d %H:%M:%S"`;" EXIT

cpu_num="$(/usr/bin/env php -r "echo swoole_cpu_num() * 2;")"

if [ "$SWOOLE_CI_IN_MACOS" = 1 ]; then
    cpu_num=1
else
    options="-j${cpu_num}"
fi

echo "" && echo "🌵️️ Current branch is ${SWOOLE_BRANCH}" && echo ""
if [ "${SWOOLE_BRANCH}" = "valgrind" ]; then
    dir="base"
    options="${options} -m"
elif [ "$SWOOLE_THREAD" = 1 ]; then
    dir="swoole_thread"
elif [ "$SWOOLE_IOURING" = 1 ]; then
    dir="swoole_runtime/file_hook swoole_iouring"
elif [ "$SWOOLE_CI_IN_MACOS" = 1 ]; then
    dir="swoole_atomic swoole_coroutine swoole_coroutine_wait_group swoole_global swoole_http_server swoole_process_pool  swoole_server_port \
     swoole_websocket_server swoole_channel_coro swoole_coroutine_lock swoole_curl swoole_http2_client_coro swoole_http_server_coro  \
     swoole_redis_server swoole_socket_coro swoole_client_async swoole_coroutine_scheduler swoole_event swoole_http2_server \
    swoole_runtime swoole_table swoole_client_coro swoole_coroutine_system  swoole_feature swoole_http2_server_coro swoole_library swoole_server \
    swoole_client_sync   swoole_coroutine_util   swoole_function swoole_http_client_coro  swoole_lock swoole_process swoole_server_coro swoole_timer"
else
    dir="swoole_*"
fi
echo "${dir}"
echo "${dir}" > tests.list
for i in 1 2 3 4 5
do
    if [ "`has_failures`" ]; then
        if [ ${i} -gt "1" ]; then
            sleep ${i}
            echo "" && echo "😮 Retry failed tests#${i}:" && echo ""
        fi
        cat tests.list
        timeout=`echo | expr ${i} \* 15 + 15`
        options="${options} --set-timeout ${timeout}"
        run_tests tests.list "${options}"
    else
        break
    fi
done
if [ "`should_exit_with_error`" ]; then
    exit 255
fi
