<?php

$start = microtime(true);

$cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
$cli->on("connect", function(swoole_client $cli) {
    assert(false);
});
$cli->on("receive", function(swoole_client $cli, $data) {
    assert(false);
});
$cli->on("error", function(swoole_client $cli) {
    echo "error\n";
});
$cli->on("close", function(swoole_client $cli) {
    echo "close\n";
});

function refcount($var)
{
    ob_start();
    debug_zval_dump($var);
    preg_match('/refcount\((?<refcount>\d)\)/', ob_get_clean(), $matches);
    return intval($matches["refcount"]) - 3;
}

@$cli->connect("11.11.11.11", 9000, 0.1);
@$cli->connect("11.11.11.11", 9000, 0.1);
@$cli->connect("11.11.11.11", 9000, 0.1);
@$cli->connect("11.11.11.11", 9000, 0.1);
@$cli->connect("11.11.11.11", 9000, 0.1);
Swoole\Event::wait();
// xdebug_debug_zval("cli");
// echo refcount($cli); // php7无效