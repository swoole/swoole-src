--TEST--
swoole_client_async: getSocket debug
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
if (method_exists('swoole_client', 'getSocket') === false) {
    exit("require sockets supports.");
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/simple_server.php";
start_server($simple_tcp_server, TCP_SERVER_HOST, TCP_SERVER_PORT);

$timer = suicide(1000);

$cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

$cli->on("connect", function (swoole_client $cli) use ($timer) {
    // getSocket BUG
    $cli->getSocket();
    $cli->getSocket();

    echo "SUCCESS\n";
    /*
    @$cli->getSocket();
    $err = error_get_last();
    Assert::same($err["message"], "swoole_client_async::getSocket(): unable to obtain socket family Error: Bad file descriptor[9].");
    */
    $cli->close();
    Swoole\Timer::clear($timer);
});

$cli->on("receive", function (swoole_client $cli, $data) {
});
$cli->on("error", function (swoole_client $cli) {
    echo "error\n";
});
$cli->on("close", function (swoole_client $cli) {
});

$cli->connect(TCP_SERVER_HOST, TCP_SERVER_PORT, 1);
Swoole\Event::wait();
?>
--EXPECT--
SUCCESS
