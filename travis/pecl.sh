#!/bin/sh -e
pecl config-show && \
pecl package && package_file="`ls | grep swoole-*tgz`" && \
echo "\n" | pecl install -f ${package_file} | tee pecl.log && \
cat pecl.log | grep "successfully" && \
pecl uninstall swoole && \
rm -f pecl.log