#!/bin/sh
__DIR__=$(cd "$(dirname "$0")";pwd)
__SRC_DIR__=$(cd "$(dirname "${__DIR__}")";pwd)

set -e
cd "${__SRC_DIR__}"
set +e
find . \( -name \*.gcno -o -name \*.gcda \) -print0 | xargs -0 rm -f
find . \( -name \*.lo -o -name \*.o \) -print0 | xargs -0 rm -f
find . \( -name \*.la -o -name \*.a \) -print0 | xargs -0 rm -f
find . \( -name \*.dep \) -print0 | xargs -0 rm -f
find . -name \*.so -print0 | xargs -0 rm -f
find . -name .libs -a -type d -print0 | xargs -0 rm -rf
rm -f libphp.la modules/* libs/*
