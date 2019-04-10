--TEST--
swoole_client_async: connect & dns
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

$cli->on("connect", function (swoole_client $cli) {
    Assert::true($cli->isConnected());
    $cli->send("GET / HTTP/1.1\r\nHost: www.baidu.com\r\nUser-Agent: curl/7.50.1-DEV\r\nAccept: */*\r\n\r\n");
});

$cli->on("receive", function (swoole_client $cli, $data) {
    assert(strlen($data) > 0);
    $cli->close();
    Assert::false($cli->isConnected());
});

$cli->on("error", function (swoole_client $cli) {
    echo "ERROR";
});

$cli->on("close", function (swoole_client $cli) {
    echo "SUCCESS";
});

$cli->connect("www.baidu.com", 80, 2.0);

swoole_event::wait();
?>
--EXPECT--
SUCCESS
