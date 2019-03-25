--TEST--
swoole_client_async: connect_host_not_found
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

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
});
$cli->on("close", function(swoole_client $cli) {
    echo "close\n";
});

$cli->connect("192.0.0.1", 9000, 0.1);
?>
--EXPECT--
error