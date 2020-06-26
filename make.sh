#!/bin/sh -e
__DIR__=$(cd "$(dirname "$0")";pwd)

cd ${__DIR__}
phpize --clean

# thirtparty
git submodule init
git submodule update

phpize
./configure --enable-openssl --enable-sockets --enable-mysqlnd --enable-http2
make clean
make -j 8
make install
