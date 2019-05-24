#!/bin/sh
__DIR__=$(cd "$(dirname "$0")";pwd)

set -e
cd ${__DIR__}
set +e
echo "rm swoole_runtime.lo"
rm swoole_runtime.lo
echo "rm library/*.h"
rm library/*.h
set -e
/usr/bin/env php tools/build-library.php
echo "done"
make $* > /dev/null
