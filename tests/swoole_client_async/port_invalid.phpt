--TEST--
swoole_client_async: port invalid
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$cli = new Swoole\Async\Client(SWOOLE_SOCK_TCP);

$cli->on("connect", function (Swoole\Async\Client $cli) {

});

$cli->on("receive", function (Swoole\Async\Client $cli, $data) {
});

$cli->on("error", function (Swoole\Async\Client $cli) {

});

$cli->on("close", function (Swoole\Async\Client $cli) {

});

Assert::false(@$cli->connect("www.baidu.com", null, 2.0));
Assert::same(swoole_last_error(), SWOOLE_ERROR_INVALID_PARAMS);

Swoole\Event::wait();
?>
--EXPECT--
