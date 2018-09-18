#!/usr/bin/env bash
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

clear_php()
{
  ps -A | grep \.php$ | grep -v phpstorm | grep -v php-fpm | awk '{print $1}' | xargs kill -9 > /dev/null 2>&1
}

clear_php
export TEST_PHP_EXECUTABLE=`which php`
glob='swoole_*'
[ -z "$1" ] || glob="$@"
${TEST_PHP_EXECUTABLE} -d "memory_limit=1024m" ${__DIR__}/run-tests ${glob}
clear_php

rm -f /tmp/swoole.log > /dev/null 2>&1
