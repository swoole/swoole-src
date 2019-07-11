--TEST--
swoole_server/task: task & finish
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$simple_tcp_server = __DIR__ . "/../../include/api/swoole_server/tcp_task_server.php";
$port = get_one_free_port();
$closeServer = start_server($simple_tcp_server, TCP_SERVER_HOST, $port);

$cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

$cli->on("connect", function(swoole_client $cli) {
    Assert::true($cli->isConnected());
    $cli->send("Test swoole_server::task Interface.");
});

$cli->on("receive", function(swoole_client $cli, $data){
    //echo "RECEIVE: $data\n";
    Assert::same($data, "OK");
    $cli->close();
    Assert::false($cli->isConnected());
});

$cli->on("error", function(swoole_client $cli) {
    echo "ERROR\n";
});

$cli->on("close", function(swoole_client $cli) use($closeServer) {
    echo "SUCCESS\n";
    $closeServer();
});

$cli->connect(TCP_SERVER_HOST, $port);

Swoole\Event::wait();
?>
--EXPECT--
SUCCESS
