#!/bin/sh -e

if [ "${TRAVIS}"x = ""x ]; then
  echo "\n❌ This script is just for Travis!"
  exit 255
fi

phpize > /dev/null && \
./configure > /dev/null && \
make clean > /dev/null && \
make > /dev/null | tee /tmp/compile.log && \
(test "`cat /tmp/compile.log`"x = ""x || exit 255) && \
make install && \
echo "\n[swoole]\nextension=swoole.so" >> ~/.phpenv/versions/$(phpenv version-name)/etc/php.ini
