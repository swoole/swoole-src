#!/bin/sh -e
source ./core.sh
#-----------compile------------
cd ${__DIR__} && cd ../ && \
phpize && \
./configure \
--enable-openssl  \
--enable-http2  \
--enable-async-redis \
--enable-sockets \
--enable-mysqlnd && \
make && make install && \
docker-php-ext-enable swoole && \
echo "swoole.fast_serialize=On" >> /usr/local/etc/php/conf.d/docker-php-ext-swoole-serialize.ini