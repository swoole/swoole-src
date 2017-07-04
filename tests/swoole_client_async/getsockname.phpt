--TEST--
swoole_client: swoole_client getsockname

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/simple_server.php";
start_server($simple_tcp_server, TCP_SERVER_HOST, TCP_SERVER_PORT);

suicide(5000);


$cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

$cli->on("connect", function(swoole_client $cli) {
    assert($cli->isConnected() === true);

    $i = $cli->getsockname();
    assert($i !== false);
    assert($i["host"] === "127.0.0.1");

    $cli->close();
});

$cli->on("receive", function(swoole_client $cli, $data){
});

$cli->on("error", function(swoole_client $cli) {
    echo "error";
});

$cli->on("close", function(swoole_client $cli) {
    echo "SUCCESS";
    swoole_event_exit();
});

$cli->connect(TCP_SERVER_HOST, TCP_SERVER_PORT, 1);
Swoole\Event::wait();
?>

--EXPECT--
SUCCESS