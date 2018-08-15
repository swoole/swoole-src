#!/bin/sh -e
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

#-----------compile------------
#-------print error only-------
cd ${__DIR__} && cd ../ && \
phpize > /dev/null && \
./configure \
--enable-openssl  \
--enable-http2  \
--enable-async-redis \
--enable-sockets \
--enable-mysqlnd \
> /dev/null && \
make clean > /dev/null && \
make > /dev/null && make install && \
docker-php-ext-enable swoole && \
echo "swoole.fast_serialize=On" >> /usr/local/etc/php/conf.d/docker-php-ext-swoole-serialize.ini