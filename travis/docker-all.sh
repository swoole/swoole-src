#!/bin/sh -e
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

cd ${__DIR__} && \
pwd && \
ls -al / && \
php -v && \
./docker-compile.sh && \
./docker-test.sh