<?php


require_once __DIR__ . "/../../../include/bootstrap.php";



suicide(5000);


$cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

/** @noinspection PhpVoidFunctionResultUsedInspection */
assert($cli->set([
    // TODO test
    // 'open_eof_check' => true,
    // 'package_eof' => "\r\n\r\n",

    // TODO
    // "socket_buffer_size" => 1,
]));

$cli->on("connect", function(swoole_client $cli) {
    swoole_timer_clear($cli->timeo_id);

    // TODO getSocket BUG
    // assert(is_resource($cli->getSocket()));
    /*
    $cli->getSocket();
    // Warning: swoole_client_async::getSocket(): unable to obtain socket family Error: Bad file descriptor[9].
    $cli->getSocket();
     */


    assert($cli->isConnected() === true);
    $cli->send(RandStr::gen(1024, RandStr::ALL));
    // $cli->sendfile(__DIR__.'/test.txt');
});

$cli->on("receive", function(swoole_client $cli, $data){
    $recv_len = strlen($data);
    debug_log("receive: len $recv_len");
    $cli->send(RandStr::gen(1024, RandStr::ALL));
    $cli->close();
    assert($cli->isConnected() === false);
});

$cli->on("error", function(swoole_client $cli) {
    swoole_timer_clear($cli->timeo_id);
    debug_log("error");
});

$cli->on("close", function(swoole_client $cli) {
    swoole_timer_clear($cli->timeo_id);
    debug_log("close");
});

$cli->connect(TCP_SERVER_HOST, TCP_SERVER_PORT);
$cli->timeo_id = swoole_timer_after(1000, function() use($cli) {
    debug_log("connect timeout");
    $cli->close();
    assert($cli->isConnected() === false);
});
