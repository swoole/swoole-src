#!/bin/sh -e
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

if [ "${TRAVIS}"x = ""x ]; then
  echo "\n❌ This script is just for Travis!"
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
echo "\n[swoole]\nextension=swoole.so" >> ~/.phpenv/versions/$(phpenv version-name)/etc/php.ini
