--TEST--
swoole_server: task
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/6/7
 * Time: 下午4:34
 */
require_once __DIR__ . "/../include/swoole.inc";

/*
$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/opcode_server.php";
$port = get_one_free_port();
//
start_server($simple_tcp_server, TCP_SERVER_HOST, $port);
//
suicide(2000);
usleep(500 * 1000);

makeTcpClient(TCP_SERVER_HOST, $port, swoole_function(\swoole_client_async $cli) {
    $r = $cli->send(opcode_encode("task", ['{"fd":2, "data":"SUCCESS"}']));
    assert($r !== false);
}, swoole_function(\swoole_client_async $cli, $recv) {
    list($op, $data) = opcode_decode($recv);
    // TODO coredump
    // 会收到两条消息, 第二条会收到success
    var_dump($data);

//    swoole_timer_after(100, swoole_function() {
        // swoole_event_exit();
//        echo "SUCCESS";
//    });
});
*/
$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/tcp_task_server.php";
start_server($simple_tcp_server, TCP_SERVER_HOST, TCP_SERVER_PORT);

suicide(5000);

$cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);


$cli->on("connect", function(swoole_client $cli) {
    swoole_timer_clear($cli->timeo_id);
    assert($cli->isConnected() === true);
    $cli->send("Test swoole_server::task Interface.");
});

$cli->on("receive", function(swoole_client $cli, $data){
    echo "$data\n";
    $cli->close();
    assert($cli->isConnected() === false);
});

$cli->on("error", function(swoole_client $cli) {
    print("error");
});

$cli->on("close", function(swoole_client $cli) {
    swoole_event_exit();
    echo "SUCCESS";
});

$cli->connect(TCP_SERVER_HOST, TCP_SERVER_PORT);
$cli->timeo_id = swoole_timer_after(1000, function() use($cli) {
    print("connect timeout");
    $cli->close();
    assert($cli->isConnected() === false);
});

?>
--EXPECT--
Test swoole_server::task Interface.
SUCCESS
