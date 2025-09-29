#!/bin/sh -e
__CURRENT__=$(pwd)
__DIR__=$(cd "$(dirname "$0")";pwd)

if [ ! -f "/.dockerenv" ]; then
    echo "" && echo "❌ This script is just for Docker!"
    exit
fi

sh library.sh

cd "${__DIR__}" && cd ..

./scripts/clear.sh && phpize
if [ -n "$(php -v | grep "ZTS")" ]; then
   echo "" && echo "🚀 php zts + swoole thread mode + iouring!"
  ./configure --enable-iouring --enable-swoole-thread
else
  echo "" && echo "🚀 php nts + swoole + iouring!"
  ./configure --enable-iouring
fi

make -j$(cat /proc/cpuinfo | grep processor | wc -l)
make install
docker-php-ext-enable swoole
php -v
php -m
php --ri curl
php --ri swoole

