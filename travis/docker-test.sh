#!/bin/sh -e
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

#-------------PHPT-------------
cd ${__DIR__} && cd ../tests/
# initialization
php ./init.php
# run
./start.sh ./swoole_coroutine ./swoole_redis_coro ./swoole_mysql_coro \
--set-timeout 15 --show-diff