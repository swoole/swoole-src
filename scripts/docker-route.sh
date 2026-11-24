#!/bin/sh -e
__CURRENT__=$(pwd)
__DIR__=$(cd "$(dirname "$0")";pwd)

# show system info and php info
date && echo ""
uname -a && echo ""
php -v && echo ""

# enter the dir
cd "${__DIR__}"

build_jobs=1
if [ -f /.cienv ]; then
  build_jobs=$(nproc)
fi
export SWOOLE_BUILD_JOBS=$build_jobs
export SWOOLE_TEST_JOBS=${SWOOLE_TEST_JOBS:-$build_jobs}
export CMAKE_BUILD_PARALLEL_LEVEL=$build_jobs PHP_COMPILER_JOBS=$build_jobs CARGO_BUILD_JOBS=$build_jobs
export MAKEFLAGS=-j$build_jobs MFLAGS=-j$build_jobs

if [ "$1" = "THREAD" ]; then
  export SWOOLE_THREAD=1
elif [ "$1" = "IOURING" ]; then
  export SWOOLE_IOURING=1
fi

# compile in docker
echo "" && echo "📦 Compile test in docker..." && echo ""
./docker-compile.sh

# PHPT workers already run concurrently; keep any build started by a test serial.
export SWOOLE_BUILD_JOBS=1 CMAKE_BUILD_PARALLEL_LEVEL=1 PHP_COMPILER_JOBS=1 CARGO_BUILD_JOBS=1
export MAKEFLAGS=-j1 MFLAGS=-j1

# run unit tests
echo "" && echo "📋 PHP unit tests in docker..." && echo ""
./run-tests.sh
