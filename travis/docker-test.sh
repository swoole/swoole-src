#!/bin/sh -e
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

#-------------PHPT-------------
cd ${__DIR__} && cd ../tests/
# initialization
php ./init
# debug
for debug_file in ./debug/*.php
do
    if test -f "${debug_file}";then
        echo "====== Run debug File ${debug_file} ======\n"
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
    --set-timeout 45 \
    --show-diff \
    -w failed.list \
    "${failed_list}"
}

# it need too much time, so we can only run the part of these
for dir in "*"
do
    ./start.sh \
    --set-timeout 25 \
    --show-diff \
    -w failed.list \
    "./swoole_${dir}"

    for i in 1 2 3 4 5
    do
        if [ "`cat failed.list | grep "phpt"`" ]; then
            sleep ${i}
            echo "retry#${i}..."
            retry_failures
        else
            exit 0
        fi
    done

    if [ "`cat failed.list | grep "phpt"`" ]; then
        exit 255
    fi
done
