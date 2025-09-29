--TEST--
swoole_client_async: Swoole\Async\Client connect & send & close
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/simple_server.php";
start_server($simple_tcp_server, TCP_SERVER_HOST, TCP_SERVER_PORT);

suicide(5000);

$cli = new Swoole\Async\Client(SWOOLE_SOCK_TCP);

$cli->on("connect", function(Swoole\Async\Client $cli) {
    Assert::true($cli->isConnected());
    $cli->send(RandStr::gen(1024, RandStr::ALL));
});

$cli->on("receive", function(Swoole\Async\Client $cli, $data){
    $recv_len = strlen($data);
    // print("receive: len $recv_len");
    $cli->send(RandStr::gen(1024, RandStr::ALL));
    $cli->close();
    Assert::false($cli->isConnected());
});

$cli->on("error", function(Swoole\Async\Client $cli) {
    print("error");
});

$cli->on("close", function(Swoole\Async\Client $cli) {
    Swoole\Event::exit();
    echo "SUCCESS";
});

$cli->connect(TCP_SERVER_HOST, TCP_SERVER_PORT, 0.2);
Swoole\Event::wait();
?>
--EXPECT--
SUCCESS
