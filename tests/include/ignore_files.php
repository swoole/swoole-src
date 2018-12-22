<?php
$root = dirname(__DIR__);
$ignore_files = [
    $root . "/swoole_async/big_zero",
    $root . "/swoole_async/big_zero.copy",
    $root . "/swoole_client_async/test.jpg",
    $root . "/swoole_process/echo.py",
    $root . "/swoole_serialize/skipif.inc",
    $root . "/swoole_http_server/httpdata",
];

return $ignore_files;
