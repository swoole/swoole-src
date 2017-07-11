<?php

require_once  __DIR__ . "/config.php";
require_once __DIR__ . "/toolkit/RandStr.php";
require_once __DIR__ . "/toolkit/TcpStat.php";
require_once __DIR__ . "/toolkit/functions.php";


ini_set("assert.active", 1);
assert_options(ASSERT_ACTIVE, 1);
assert_options(ASSERT_WARNING, 1);
assert_options(ASSERT_BAIL, 0);
assert_options(ASSERT_QUIET_EVAL, 0);

ini_set("memory_limit", "1024M");
ini_set("swoole.aio_mode", SWOOLE_AIO_BASE); // SWOOLE_AIO_BASE, SWOOLE_AIO_LINUX

swoole_async_set([
    "socket_dontwait" => 1,
    "aio_mode" => SWOOLE_AIO_BASE,
    "thread_num" => 1,
    'disable_dns_cache' => true,
    'dns_lookup_random' => true,
]);