#!/bin/sh -e
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

#-------------PHPT-------------
cd ${__DIR__} && cd ../tests/
# initialization
php ./init.php
# run
./start.sh \
--set-timeout 25 \
--show-diff \
-w failed.list \
./swoole_*

if [ "`cat failed.list | grep "phpt"`" ]; then
    # replace \n to space
    failed_list="`tr '\n' ' ' < failed.list`"

    # and retry
    ./start.sh \
    --set-timeout 45 \
    --show-diff \
    -w failed.list \
    "${failed_list}"

    if [ "`cat failed.list | grep "phpt"`" ]; then
        exit 255
    fi
fi