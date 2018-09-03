#!/bin/sh -e
pecl config-show && \
pecl package && \
package_file="`ls | grep swoole-*tgz`" && \
install_info="`echo "\n" | pecl install -f ${package_file}`" && \
echo "${install_info}" && echo "${install_info}" | grep "successfully" && \
pecl uninstall swoole