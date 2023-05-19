#!/bin/sh -e
__CURRENT__=$(pwd)
__DIR__=$(cd "$(dirname "$0")";pwd)

sh instantclient.sh

if [ ! -f "/.dockerenv" ]; then
    echo "" && echo "❌ This script is just for Docker!"
    exit
fi

cd "${__DIR__}" && cd ..
./scripts/clear.sh
phpize
./configure \
--enable-openssl \
--enable-sockets \
--enable-mysqlnd \
--enable-swoole-curl \
--enable-cares \
--enable-swoole-pgsql \
--with-pdo-odbc=unixODBC,/usr \
--with-swoole-oracle=instantclient,/usr/local/instantclient

make -j$(cat /proc/cpuinfo | grep processor | wc -l)
make install
docker-php-ext-enable swoole
php -v
php -m
php --ri curl
php --ri swoole

