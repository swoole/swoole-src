--TEST--
swoole_client: swoole_client sleep & sleep

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

    $r = $cli->sleep();
    assert($r);
    swoole_timer_after(200, function() use($cli) {
        $r = $cli->wakeup();
        assert($r);
    });
    $cli->send(RandStr::gen(1024, RandStr::ALL));
});

$cli->on("receive", function(swoole_client $cli, $data){
    $recv_len = strlen($data);
    $cli->send(RandStr::gen(1024, RandStr::ALL));
    $cli->close();
    assert($cli->isConnected() === false);
});

$cli->on("error", function(swoole_client $cli) {
    echo "error";
});

$cli->on("close", function(swoole_client $cli) {
    swoole_event_exit();
    echo "SUCCESS";
});

$cli->connect(TCP_SERVER_HOST, TCP_SERVER_PORT, 0.1);
Swoole\Event::wait();

?>

--EXPECT--
SUCCESS