#!/usr/bin/env php
<?php
if (isset($argv[1]) and $argv[1] == 'dev') {
    putenv('SWOOLE_LIBRARY_DEV=1');
}
$argv[1] = realpath(__DIR__ . '/../library/src');
putenv('SWOOLE_DIR=' . realpath(__DIR__ . '/..'));
require __DIR__ . '/vendor/bin/make-library.php';
