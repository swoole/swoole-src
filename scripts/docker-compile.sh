#!/bin/sh -e
__CURRENT__=$(pwd)
__DIR__=$(
  cd "$(dirname "$0")"
  pwd
)

if [ ! -f "/.dockerenv" ]; then
  echo "" && echo "❌ This script is just for Docker!"
  exit
fi

sh library.sh

CONFIGURE_FLAGS="--enable-openssl \
--enable-sockets \
--enable-mysqlnd \
--enable-swoole-curl \
--enable-cares \
--enable-swoole-pgsql \
--with-swoole-odbc=unixODBC,/usr \
--with-swoole-oracle=instantclient,/usr/local/instantclient \
--enable-swoole-sqlite"

echo "file async driver is $SWOOLE_FILE_DRIVER ✅"
if [ $SWOOLE_FILE_DRIVER = "iouring" ]; then
  CONFIGURE_FLAGS="${CONFIGURE_FLAGS} --enable-iouring"
fi

cd "${__DIR__}" && cd ..
./scripts/clear.sh && phpize && ./configure ${CONFIGURE_FLAGS}

make -j$(cat /proc/cpuinfo | grep processor | wc -l)
make install
docker-php-ext-enable swoole
php -v
php -m
php --ri curl
php --ri swoole
