#!/bin/sh -e
__CURRENT__=$(pwd)
__DIR__=$(
    cd "$(dirname "$0")"
    pwd
)

cd ${__DIR__}
cd ../
pecl config-show
php ../tools/pecl-package.php
PACKAGE_FILE="$(ls | grep swoole-*tgz)" pecl install -f ${PACKAGE_FILE}
cat pecl.log | grep "successfully"
pecl uninstall swoole
rm -f pecl.log
