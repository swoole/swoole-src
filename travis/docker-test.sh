#!/bin/sh -e
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

#-------------PHPT-------------
cd ${__DIR__} && cd ../tests/
# initialization
php ./init.php
# run
./start.sh --set-timeout 15 --show-diff -w failed.list ./

if [ "`cat failed.list | grep "phpt"`" ]; then
    exit 1
fi