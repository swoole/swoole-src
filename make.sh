#!/bin/sh -e
__DIR__=$(cd "$(dirname "$0")";pwd)

cd ${__DIR__}
phpize --clean

# thirtparty
git submodule init
git submodule update

phpize
if [ "$1" = "debug" ] ;then
  ./configure --enable-openssl --enable-swoole-json --enable-swoole-curl --enable-sockets --enable-mysqlnd --enable-http2 --enable-debug-log
else
  ./configure --enable-openssl --enable-swoole-json --enable-swoole-curl --enable-sockets --enable-mysqlnd --enable-http2
fi
make clean
make -j 8
make install
