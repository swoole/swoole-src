--TEST--
swoole_client_async: swoole_client getsockname
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/simple_server.php";
start_server($simple_tcp_server, TCP_SERVER_HOST, TCP_SERVER_PORT);

$timer = suicide(5000);

$cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

$cli->on("connect", function (swoole_client $cli) use ($timer) {
    Assert::true($cli->isConnected());

    $i = $cli->getsockname();
    Assert::assert($i !== false);
    Assert::eq($i["host"], '127.0.0.1');

    $cli->close();
    swoole_timer::clear($timer);
});

$cli->on("receive", function (swoole_client $cli, $data) {
});

$cli->on("error", function (swoole_client $cli) {
    echo "error";
});

$cli->on("close", function (swoole_client $cli) {
    echo "SUCCESS";
    swoole_event_exit();
});

$cli->connect(TCP_SERVER_HOST, TCP_SERVER_PORT, 1);
Swoole\Event::wait();
?>
--EXPECT--
SUCCESS
