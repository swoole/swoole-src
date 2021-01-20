#!/bin/sh -e
__DIR__=$(cd "$(dirname "$0")";pwd)
__EXT_DIR__=$(php-config --extension-dir)
COMPILE_PARAMS="--enable-openssl --enable-sockets --enable-mysqlnd --enable-http2 --enable-swoole-json --enable-swoole-curl"

cd "${__DIR__}"

if [ "$1" = "cmake" ] ;then
  phpize
  ./configure ${COMPILE_PARAMS}
  cmake .
  make -j 8
  exit 0
fi

if [ "$1" = "clean" ] ;then
  make clean
  phpize --clean
  exit 0
fi

if [ "$1" = "install-module" ] ;then
  make ext-swoole
  cp lib/swoole.so "${__EXT_DIR__}"
  echo "cp lib/swoole.so ${__EXT_DIR__}"
  exit 0
fi

if [ "$1" = "sync-module" ] ;then
  # thirdparty
  git submodule init
  git submodule update
  exit 0
fi

if [ "$1" = "library" ] ;then
  set -e
  cd ${__DIR__}
  set +e
  echo "rm ext-src/php_swoole.lo"
  rm -f ext-src/php_swoole.lo
  echo "rm ext-src/php_swoole_library.h"
  rm -f ext-src/php_swoole_library.h
  set -e

  if [ "$2" = "dev" ] ;then
    /usr/bin/env php tools/build-library.php dev
  else
     /usr/bin/env php tools/build-library.php
  fi

  echo "remake..."
  make
  echo "done"
  exit 0
fi

if [ "$1" = "help" ] ;then
  echo "./make.sh cmake"
  echo "./make.sh install-module"
  echo "./make.sh sync-module"
  echo "./make.sh clean"
  echo "./make.sh debug"
  echo "./make.sh library [dev]"
  echo "./make.sh"
  exit 0
fi

phpize
if [ "$1" = "debug" ] ;then
  ./configure ${COMPILE_PARAMS} --enable-debug-log
else
  ./configure ${COMPILE_PARAMS}
fi
make clean
make -j 8
make install
