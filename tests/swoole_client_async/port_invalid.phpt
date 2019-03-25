--TEST--
swoole_client_async: port invalid
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

$cli->on("connect", function (swoole_client $cli) {

});

$cli->on("receive", function (swoole_client $cli, $data) {
});

$cli->on("error", function (swoole_client $cli) {

});

$cli->on("close", function (swoole_client $cli) {

});

Assert::false(@$cli->connect("www.baidu.com", null, 2.0));
Assert::eq(swoole_last_error(), SWOOLE_ERROR_INVALID_PARAMS);

swoole_event::wait();
?>
--EXPECT--
