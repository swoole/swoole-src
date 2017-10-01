#!/usr/bin/env bash

`pidof php | xargs kill > /dev/null 2>&1`
export TEST_PHP_EXECUTABLE=`which php`
BASEDIR=$(dirname "$0")
glob='swoole_*'
[ -z "$1" ] || glob=$1
$TEST_PHP_EXECUTABLE -d "memory_limit=1024m" $BASEDIR/run-tests $glob
`pidof php | xargs kill > /dev/null 2>&1`
