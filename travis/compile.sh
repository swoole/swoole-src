#!/bin/sh -e
phpize > /dev/null && \
./configure > /dev/null && \
make clean > /dev/null && \
make > /dev/null && make install && \
echo "\n[swoole]\nextension=swoole.so" >> ~/.phpenv/versions/$(phpenv version-name)/etc/php.ini