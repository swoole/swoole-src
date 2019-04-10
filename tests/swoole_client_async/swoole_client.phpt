--TEST--
swoole_client_async: swoole_client connect & send & close
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/simple_server.php";
start_server($simple_tcp_server, TCP_SERVER_HOST, TCP_SERVER_PORT);

suicide(5000);

$cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

$cli->on("connect", function(swoole_client $cli) {
    Assert::true($cli->isConnected());
    $cli->send(RandStr::gen(1024, RandStr::ALL));
});

$cli->on("receive", function(swoole_client $cli, $data){
    $recv_len = strlen($data);
    // print("receive: len $recv_len");
    $cli->send(RandStr::gen(1024, RandStr::ALL));
    $cli->close();
    Assert::false($cli->isConnected());
});

$cli->on("error", function(swoole_client $cli) {
    // swoole_timer_clear($cli->timeo_id);
    print("error");
});

$cli->on("close", function(swoole_client $cli) {
    // swoole_timer_clear($cli->timeo_id);
    // print("close");
    swoole_event_exit();
    echo "SUCCESS";
});

$cli->connect(TCP_SERVER_HOST, TCP_SERVER_PORT, 0.2);

?>
--EXPECT--
SUCCESS
