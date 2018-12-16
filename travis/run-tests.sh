#!/bin/sh -e
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

#-------------PHPT-------------
cd ${__DIR__} && cd ../tests/

# initialization
echo "\n⭐️ Initialization for tests...\n"
php ./init
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

# run tests
retry_failures()
{
    # replace \n to space
    failed_list="`tr '\n' ' ' < failed.list`"

    # and retry
    ./start.sh \
    --set-timeout $1 \
    --show-slow 1000 \
    --show-diff \
    -w failed.list \
    "${failed_list}"
}

# it need too much time, so we can only run the part of these
for dir in "*"
do
    ./start.sh \
    --set-timeout 10 \
    --show-slow 1000 \
    --show-diff \
    -w failed.list \
    "./swoole_${dir}"

    for i in 1 2 3
    do
        if [ "`cat failed.list | grep "phpt"`" ]; then
            sleep ${i}
            echo "\n😮 Retry failed tests #${i}:\n"
            cat failed.list
            retry_failures "`echo | expr ${i} \* 10`"
        else
            exit 0
        fi
    done

    if [ "`cat failed.list | grep "phpt"`" ]; then
        exit 255
    fi
done
