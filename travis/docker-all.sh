#!/bin/sh -e
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

# show info
cd ${__DIR__} && pwd && ls -al / && php -v

# compile in docker
./docker-compile.sh

# swoole info
php --ri swoole

#alpine
if [ "`apk | grep apk-tools`"x != ""x ]; then
  echo "skip alpine\n"
  exit 0
fi

# run unit tests
./docker-test.sh
