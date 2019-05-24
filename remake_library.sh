#!/bin/sh
echo "rm swoole_runtime.lo"
rm swoole_runtime.lo
echo "rm library/*.h"
rm library/*.h
/usr/bin/env php tools/build-library.php
echo "done"
make $*
