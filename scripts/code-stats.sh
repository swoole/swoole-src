#!/bin/sh -e
__CURRENT__=$(pwd)
__DIR__=$(cd "$(dirname "$0")";pwd)

# enter the dir
cd "${__DIR__}/.."
cloc . --exclude-dir=thirdparty,Debug,CMakeFiles,build,.git \
  --fullpath \
  --not-match-d='tools/vendor' \
  --not-match-d='tests/include/lib/vendor' \
  --not-match-f='ext-src/php_swoole_library\.h$'
