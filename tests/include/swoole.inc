<?php
require_once  __DIR__ . "/config.php";
require_once __DIR__ . "/toolkit/RandStr.php";
require_once __DIR__ . '/../include/lib/curl.php';

ini_set("memory_limit", "1024M");
ini_set("swoole.aio_mode", SWOOLE_AIO_BASE); // SWOOLE_AIO_BASE, SWOOLE_AIO_LINUX

swoole_async_set([
    "socket_dontwait" => 1,
    "aio_mode" => SWOOLE_AIO_BASE,
    "thread_num" => 1,
    'disable_dns_cache' => true,
    'dns_lookup_random' => true,
]);