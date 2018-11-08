#!/bin/sh -e
phpize > /dev/null && \
./configure > /dev/null && \
make clean > /dev/null && \
make > /dev/null | tee /tmp/compile.log && \
(test "`cat /tmp/compile.log`" = "" || exit 255) && \
make install && \
echo "\n[swoole]\nextension=swoole.so" >> ~/.phpenv/versions/$(phpenv version-name)/etc/php.ini
