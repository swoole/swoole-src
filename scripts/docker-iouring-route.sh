#!/bin/sh -e
__CURRENT__=$(pwd)
__DIR__=$(cd "$(dirname "$0")";pwd)
export SWOOLE_USE_IOURING=1

# enter the dir
cd "${__DIR__}"

# show system info
date && echo ""
uname -a && echo ""

# show php info
php -v && echo ""

# compile in docker
echo "" && echo "📦 Compile ext-swoole[iouring] in docker..." && echo ""
./docker-compile-with-iouring.sh

# run unit tests
echo "" && echo "📋 Run php tests[iouring] in docker..." && echo ""
./run-tests.sh

