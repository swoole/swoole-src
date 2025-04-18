#!/bin/sh -e
__CURRENT__=$(pwd)
__DIR__=$(cd "$(dirname "$0")";pwd)

# show system info and php info
date && echo ""
uname -a && echo ""
php -v && echo ""

# enter the dir
cd "${__DIR__}"

if [ "$1" = "THREAD" ]; then
  export SWOOLE_THREAD=1
elif [ "$1" = "IOURING" ]; then
  export SWOOLE_IOURING=1
fi

# compile in docker
echo "" && echo "📦 Compile test in docker..." && echo ""
./docker-compile.sh

# run unit tests
echo "" && echo "📋 PHP unit tests in docker..." && echo ""
./run-tests.sh
