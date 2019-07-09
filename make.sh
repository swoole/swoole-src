#!/bin/sh -e
__DIR__=$(cd "$(dirname "$0")";pwd)

cd ${__DIR__}
phpize --clean
phpize
./configure --enable-openssl --enable-sockets --enable-mysqlnd --enable-http2 --enable-debug-log
make clean
make -j
make install
