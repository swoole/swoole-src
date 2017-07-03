--TEST--
swoole_client: swoole_client connect & send & close

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

$cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

$cli->on("connect", function(swoole_client $cli) {
    assert($cli->isConnected() === true);
    $cli->send(RandStr::gen(1024, RandStr::ALL));
});

$cli->on("receive", function(swoole_client $cli, $data){
    $recv_len = strlen($data);
    // print("receive: len $recv_len");
    $cli->send(RandStr::gen(1024, RandStr::ALL));
    $cli->close();
    assert($cli->isConnected() === false);
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
