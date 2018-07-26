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

for i in 1 2 3
do
    if [ "`cat failed.list | grep "phpt"`" ]; then
        echo "retry#${i}..."
        retry_failures
    else
        exit 0
    fi
done

exit 255
