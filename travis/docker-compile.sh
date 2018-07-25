#!/bin/sh -e
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

#-----------compile------------
cd ${__DIR__} && cd ../ && \
phpize && \
./configure \
--enable-openssl  \
--enable-http2  \
--enable-async-redis \
--enable-sockets \
--enable-mysqlnd && \
make && install_info="`make install`" && \
echo "${install_info}" && php_ext_dir="`echo "${install_info}" | grep -o " /.*extensions\/no-debug.*\/"`" && \
chmod -R 777 /usr/local/lib/php/ && \
ls -al ${php_ext_dir} && \
docker-php-ext-enable swoole && \
echo "swoole.fast_serialize=On" >> /usr/local/etc/php/conf.d/docker-php-ext-swoole-serialize.ini