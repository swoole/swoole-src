#!/bin/sh
phpize > /dev/null && \
./configure > /dev/null && \
make clean > /dev/null && \
make > /dev/null && install_info="`make install`" && \
echo "${install_info}" && php_ext_dir="`echo "${install_info}" | grep -o " /.*extensions\/no-debug.*\/"`" && \
echo "\n[swoole]\nextension=${php_ext_dir}swoole.so" >> ~/.phpenv/versions/$(phpenv version-name)/etc/php.ini