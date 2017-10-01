--TEST--
swoole_server: task & finish
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/tcp_task_server.php";
$port = get_one_free_port();
$closeServer = start_server($simple_tcp_server, TCP_SERVER_HOST, $port);

$cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

$cli->on("connect", function(swoole_client $cli) {
    assert($cli->isConnected() === true);
    $cli->send("Test swoole_server::task Interface.");
});

$cli->on("receive", function(swoole_client $cli, $data){
    //echo "RECEIVE: $data\n";
    assert($data == "OK");
    $cli->close();
    assert($cli->isConnected() === false);
});

$cli->on("error", function(swoole_client $cli) {
    echo "ERROR\n";
});

$cli->on("close", function(swoole_client $cli) use($closeServer) {
    echo "SUCCESS";
    $closeServer();
});

$cli->connect(TCP_SERVER_HOST, $port);
?>
--EXPECT--
SUCCESS
