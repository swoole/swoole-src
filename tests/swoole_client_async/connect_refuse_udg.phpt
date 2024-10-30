--TEST--
swoole_client_async: connect refuse with unix dgram
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$cli = new Swoole\Async\Client(SWOOLE_SOCK_UNIX_DGRAM);
$cli->on("connect", function(Swoole\Async\Client $cli) {
    Assert::true(false, 'never here');
});
$cli->on("receive", function(Swoole\Async\Client $cli, $data) {
    Assert::true(false, 'never here');
});
$cli->on("error", function(Swoole\Async\Client $cli) { echo "error\n"; });
$cli->on("close", function(Swoole\Async\Client $cli) { echo "close\n"; });

@$cli->connect("/test.sock", 0, 0.5, 1);

Swoole\Event::wait();
?>
--EXPECT--
error
