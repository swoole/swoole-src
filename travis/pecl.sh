#!/bin/sh -e
pecl config-show && \
php ./tools/pecl-package.php && package_file="`ls | grep swoole-*tgz`" && \
echo "\n" | pecl install -f ${package_file} | tee pecl.log && \
cat pecl.log | grep "successfully" && \
pecl uninstall swoole && \
rm -f pecl.log
