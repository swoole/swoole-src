#!/bin/sh -e
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

[ -z "${SWOOLE_BRANCH}" ] && export SWOOLE_BRANCH="master"

#-------------PHPT-------------
cd ${__DIR__} && cd ../tests/

# initialization
echo "\n⭐️ Initialization for tests...\n"
./init
echo "\n"

# debug
for debug_file in ${__DIR__}/debug/*.php
do
    if test -f "${debug_file}";then
        debug_file_basename="`basename ${debug_file}`"
        echo "\n====== RUN ${debug_file_basename} ======\n"
        php "${debug_file}"
        echo "\n========================================\n"
    fi
done

# run tests @params($1=list_file, $1=options)
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

echo "\n🌵️️ Current branch is ${SWOOLE_BRANCH}\n"
if [ "${SWOOLE_BRANCH}" = "valgrind" ]; then
    dir="base"
    options="-m"
else
    dir="swoole_*"
    options=""
fi
echo "${dir}" > tests.list
for i in 1 2 3
do
    if [ "`has_failures`" ]; then
        if [ ${i} -gt "1" ]; then
            sleep ${i}
            echo "\n😮 Retry failed tests#${i}:\n"
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
