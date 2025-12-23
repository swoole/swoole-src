#!/bin/sh
__CURRENT_DIR__=$(cd "$(dirname "$0")";pwd)
__DIR__=$(cd "$(dirname "${__CURRENT_DIR__}")";pwd)
__HAVE_ZTS__=$(php -v|grep ZTS)

COMPILE_PARAMS=" \
--enable-sockets \
--enable-mysqlnd \
--enable-swoole-curl \
--enable-cares \
--enable-zstd \
--enable-swoole-pgsql \
--enable-swoole-stdext \
--with-swoole-firebird \
--enable-uring-socket \
--with-swoole-ssh2 \
--enable-swoole-ftp \
--with-swoole-odbc=unixODBC,/usr \
--enable-swoole-sqlite"

TEMP=$(getopt -o ad --long asan,debug:,oci -n "$0" -- "$@")

if [ $? != 0 ]; then
  echo "Parameter parsing failed!" >&2
  exit 1
fi

eval set -- "$TEMP"

while true; do
  case "$1" in
    -a|--asan)
      ASAN=true
      shift
      ;;
    -d|--debug)
      DEBUG=true
      shift
      ;;
    --oci)
      OCI=true
      shift
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "Unsupported parameters!"
      exit 1
      ;;
  esac
done

if [ "$ASAN" = true ]; then
      COMPILE_PARAMS="$COMPILE_PARAMS --enable-asan"
fi

if [ "$DEBUG" = true ]; then
      COMPILE_PARAMS="$COMPILE_PARAMS --enable-debug"
fi

if [ "$OCI" = true ]; then
      COMPILE_PARAMS="$COMPILE_PARAMS --with-swoole-oracle=instantclient,/usr/local/instantclient"
fi

if [ -n "$__HAVE_ZTS__" ]; then
    COMPILE_PARAMS="$COMPILE_PARAMS --enable-swoole-thread"
fi

if [ "$(uname)" = "Linux" ]; then
    COMPILE_PARAMS="$COMPILE_PARAMS --enable-iouring"
fi

if [ "$(uname | grep -i darwin)"x != ""x ]; then
  CPU_COUNT="$(sysctl -n machdep.cpu.core_count)"
else
  CPU_COUNT="$(/usr/bin/nproc)"
fi
if [ -z ${CPU_COUNT} ]; then
  CPU_COUNT=4
fi

cd "${__DIR__}"

if [ "$1" = "cmake" ] ;then
  phpize
  ./configure ${COMPILE_PARAMS}
  cmake .
  make -j ${CPU_COUNT}
  make install
  exit 0
fi

if [ "$1" = "clean" ] ;then
  make clean
  phpize --clean
  exit 0
fi

if [ "$1" = "install-module" ] ;then
  make ext-swoole
  __EXT_DIR__=$(php-config --extension-dir)
  cp lib/swoole.so "${__EXT_DIR__}"
  echo "cp lib/swoole.so ${__EXT_DIR__}"
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
  echo "./make.sh clean"
  echo "./make.sh debug"
  echo "./make.sh trace"
  echo "./make.sh library [dev]"
  echo "./make.sh"
  exit 0
fi

phpize

if [ "$1" = "debug" ] ;then
  ./configure ${COMPILE_PARAMS} --enable-debug-log
elif [ "$1" = "trace" ] ;then
  ./configure ${COMPILE_PARAMS} --enable-trace-log
elif [ "$1" = "config" ] ;then
  ./configure ${COMPILE_PARAMS}
  exit 0
else
  ./configure ${COMPILE_PARAMS}
fi

make clean
make -j ${CPU_COUNT}
make install
