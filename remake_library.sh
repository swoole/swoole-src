#!/bin/sh
__DIR__=$(cd "$(dirname "$0")";pwd)

set -e
cd ${__DIR__}
set +e
echo "rm swoole.lo"
rm swoole.lo
echo "rm php_swoole_library.h"
rm php_swoole_library.h
set -e
/usr/bin/env php tools/build-library.php
echo "remake..."
make $* > /dev/null
echo "done"
