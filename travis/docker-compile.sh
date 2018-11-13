#!/bin/sh -e
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

if [ ! -f "/.dockerenv" ]; then
    echo "\n❌ This script is just for Docker env!"
    exit
fi

#-----------compile------------
#-------print error only-------
cd ${__DIR__} && cd ../ && \
phpize > /dev/null && \
./configure \
--enable-openssl \
--enable-http2 \
--enable-sockets \
--enable-mysqlnd \
> /dev/null && \
make clean > /dev/null && \
make > /dev/null | tee /tmp/compile.log && \
(test "`cat /tmp/compile.log`" = "" || exit 255) && \
make install && \
docker-php-ext-enable swoole && \
echo "swoole.fast_serialize=On" >> /usr/local/etc/php/conf.d/docker-php-ext-swoole-serialize.ini
