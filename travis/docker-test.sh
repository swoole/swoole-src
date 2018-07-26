#!/bin/sh -e
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

#-------------PHPT-------------
cd ${__DIR__} && cd ../tests/
# initialization
php ./init.php
# run
./start.sh \
--set-timeout 10 \
--show-diff \
-w failed.list \
./swoole_*

if [ "`cat failed.list | grep "phpt"`" ]; then
    # read failed list
    failed_list="`cat failed.list`"

    # replace \n to space and retry
    ./start.sh \
    --set-timeout 20 \
    --show-diff \
    -w failed.list \
    ${failed_list/\n/ }

    if [ "`cat failed.list | grep "phpt"`" ]; then
        exit 255
    fi
fi