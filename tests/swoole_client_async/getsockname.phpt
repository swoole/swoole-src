--TEST--
swoole_client_async: Swoole\Async\Client getsockname
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/simple_server.php";
start_server($simple_tcp_server, TCP_SERVER_HOST, TCP_SERVER_PORT);

$timer = suicide(5000);

$cli = new \Swoole\Async\Client(SWOOLE_SOCK_TCP);

$cli->on("connect", function (Swoole\Async\Client $cli) use ($timer) {
    Assert::true($cli->isConnected());

    $i = $cli->getsockname();
    Assert::assert($i !== false);
    Assert::same($i["host"], '127.0.0.1');

    $cli->close();
    Swoole\Timer::clear($timer);
});

$cli->on("receive", function (Swoole\Async\Client $cli, $data) {
});

$cli->on("error", function (Swoole\Async\Client $cli) {
    echo "error";
});

$cli->on("close", function (Swoole\Async\Client $cli) {
    echo "SUCCESS";
    Swoole\Event::exit();
});

$cli->connect(TCP_SERVER_HOST, TCP_SERVER_PORT, 1);
Swoole\Event::wait();
?>
--EXPECT--
SUCCESS
