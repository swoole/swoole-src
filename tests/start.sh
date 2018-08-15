#!/usr/bin/env bash

clear_php()
{
  ps -A | grep \.php$ | grep -v phpstorm | grep -v php-fpm | awk '{print $1}' | xargs kill -9 > /dev/null 2>&1
}

clear_php
export TEST_PHP_EXECUTABLE=`which php`
BASEDIR=$(dirname "$0")
glob='swoole_*'
[ -z "$1" ] || glob="$@"
${TEST_PHP_EXECUTABLE} -d "memory_limit=1024m" ${BASEDIR}/run-tests ${glob}
clear_php

rm -f /tmp/swoole.log > /dev/null 2>&1
