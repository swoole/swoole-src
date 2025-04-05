#!/bin/sh -e
__CURRENT__=$(pwd)
__DIR__=$(cd "$(dirname "$0")";pwd)

if [ ! -f "/.dockerenv" ]; then
    echo "" && echo "❌ This script is just for Docker!"
    exit
fi

sh library.sh
cd "${__DIR__}/.." && ./scripts/clear.sh
phpize

option="--enable-brotli \
       --enable-zstd \
       --enable-openssl \
       --enable-sockets \
       --enable-mysqlnd \
       --enable-swoole-curl \
       --enable-cares \
       --enable-swoole-pgsql \
       --with-swoole-odbc=unixODBC,/usr \
       --with-swoole-oracle=instantclient,/usr/local/instantclient \
       --enable-swoole-sqlite"

if [ "$SWOOLE_THREAD" = 1 ]; then
  ./configure $option --enable-swoole-thread
elif [ "$SWOOLE_IOURING" = 1 ]; then
  if [ -n "$(php -v | grep "ZTS")" ]; then
     echo "" && echo "🚀 php zts + swoole thread mode + iouring!"
    ./configure --enable-iouring --enable-swoole-thread
  else
    echo "" && echo "🚀 php nts + swoole + iouring!"
    ./configure --enable-iouring
  fi
else
  ./configure $option
fi

make -j$(cat /proc/cpuinfo | grep processor | wc -l)
make install
docker-php-ext-enable swoole
php -v
php -m
php --ri swoole

