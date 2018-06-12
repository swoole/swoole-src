#!/usr/bin/env bash

pidof_php()
{
  echo `ps -A | grep -m1 php | grep -v phpstorm | awk '{print $1}'`
}

`pidof_php | xargs kill > /dev/null 2>&1`
export TEST_PHP_EXECUTABLE=`which php`
BASEDIR=$(dirname "$0")
glob='swoole_*'
[ -z "$1" ] || glob="$@"
${TEST_PHP_EXECUTABLE} -d "memory_limit=1024m" ${BASEDIR}/run-tests ${glob}
`pidof_php | xargs kill > /dev/null 2>&1`