<?php

$start = microtime(true);

$cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
$cli->on("connect", function(swoole_client $cli) {
    assert(false);
});
$cli->on("receive", function(swoole_client $cli, $data) {
    assert(false);
});
$cli->on("error", function(swoole_client $cli) {
    echo "error\n";
    exit(0);
});
$cli->on("close", function(swoole_client $cli) {
    echo "close\n";
});

// xdebug_debug_zval("cli"); refcount = 1
$cli->connect("11.11.11.11", 9000, 0.1);
// xdebug_debug_zval("cli"); refcount = 2