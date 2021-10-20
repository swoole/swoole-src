#!/bin/sh -e
# shellcheck disable=SC2034
# shellcheck disable=SC2006
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

if [ "${GITHUB_ACTIONS}" = true ]; then
  # shellcheck disable=SC2028
  echo "\n❌ This script is just for Github!"
  exit 255
fi

sudo apt-get update -y
sudo apt-get install -y libcurl4-openssl-dev libc-ares-dev

cd "${__DIR__}" && cd ../ && \
./clear.sh > /dev/null && \
phpize --clean > /dev/null && \
phpize > /dev/null && \
./configure --enable-openssl --enable-sockets --enable-mysqlnd --enable-http2 --enable-swoole-json --enable-swoole-curl --enable-cares > /dev/null && \
make -j8 > /dev/null | tee /tmp/compile.log && \
(test "`cat /tmp/compile.log`"x = ""x || exit 255) && \
make install && \
php --ri curl && \
php -d extension=swoole.so --ri swoole
