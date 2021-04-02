#!/bin/sh -e
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

if [ "${GITHUB_ACTIONS}" = true ]; then
  echo "\n❌ This script is just for Github!"
  exit 255
fi

cd ${__DIR__} && cd ../ && \
./clear.sh > /dev/null && \
phpize --clean > /dev/null && \
phpize > /dev/null && \
./configure > /dev/null && \
make -j8 > /dev/null | tee /tmp/compile.log && \
(test "`cat /tmp/compile.log`"x = ""x || exit 255) && \
make install && \
php --ri curl && \
php -d extension=swoole.so --ri swoole
