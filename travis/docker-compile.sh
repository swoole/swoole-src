#!/bin/sh -e
__CURRENT__=$(pwd)
__DIR__=$(cd "$(dirname "$0")";pwd)

if [ ! -f "/.dockerenv" ]; then
    echo "" && echo "❌ This script is just for Docker env!"
    exit
fi

cd "${__DIR__}" && cd ..
./clear.sh
phpize
./configure \
--enable-openssl \
--enable-http2 \
--enable-sockets \
--enable-mysqlnd \
--enable-swoole-json \
--enable-swoole-curl \
--enable-cares

make -j$(nproc)
make install
docker-php-ext-enable swoole
php -v
php -m
php --ri curl
php --ri swoole

