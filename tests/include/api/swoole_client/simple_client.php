<?php


require_once __DIR__ . "/../../../include/bootstrap.php";



suicide(5000);


$cli = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

/** @noinspection PhpVoidFunctionResultUsedInspection */
assert($cli->set([
    // TODO test
    // 'open_eof_check' => true,
    // 'package_eof' => "\r\n\r\n",

    // TODO
    // "socket_buffer_size" => 1,
]));

$cli->on("connect", function(Swoole\Client $cli) {
    Swoole\Timer::clear($cli->timeo_id);

    // TODO getSocket BUG
    // assert(is_resource($cli->getSocket()));
    /*
    $cli->getSocket();
    // Warning: swoole_client_async::getSocket(): unable to obtain socket family Error: Bad file descriptor[9].
    $cli->getSocket();
     */


    Assert::true($cli->isConnected());
    $cli->send(RandStr::gen(1024, RandStr::ALL));
    // $cli->sendfile(__DIR__.'/test.txt');
});

$cli->on("receive", function(Swoole\Client $cli, $data){
    $recv_len = strlen($data);
    debug_log("receive: len $recv_len");
    $cli->send(RandStr::gen(1024, RandStr::ALL));
    $cli->close();
    Assert::false($cli->isConnected());
});

$cli->on("error", function(Swoole\Client $cli) {
    Swoole\Timer::clear($cli->timeo_id);
    debug_log("error");
});

$cli->on("close", function(Swoole\Client $cli) {
    Swoole\Timer::clear($cli->timeo_id);
    debug_log("close");
});

$cli->connect(TCP_SERVER_HOST, TCP_SERVER_PORT);
$cli->timeo_id = Swoole\Timer::after(1000, function() use($cli) {
    debug_log("connect timeout");
    $cli->close();
    Assert::false($cli->isConnected());
});
