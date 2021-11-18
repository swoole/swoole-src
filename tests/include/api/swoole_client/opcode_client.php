<?php


require_once __DIR__ . "/../../../include/bootstrap.php";



// suicide(5000);

$cli = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

/** @noinspection PhpVoidFunctionResultUsedInspection */
assert($cli->set([
    'open_length_check' => 1,
    'package_length_type' => 'N',
    'package_length_offset' => 0,
    'package_body_offset' => 0,
]));

$cli->on("connect", function(Swoole\Client $cli) {
    Swoole\Timer::clear($cli->timeo_id);
    Assert::true($cli->isConnected());

});

$cli->on("receive", function(Swoole\Client $cli, $data){

    $cli->close();
    Assert::false($cli->isConnected());
});

$cli->on("error", function(Swoole\Client $cli) {
    Swoole\Timer::clear($cli->timeo_id);
    echo "ERROR";
});

$cli->on("close", function(Swoole\Client $cli) {
    Swoole\Timer::clear($cli->timeo_id);
    echo "CLOSE";
});

$cli->connect(TCP_SERVER_HOST, TCP_SERVER_PORT);

$cli->timeo_id = Swoole\Timer::after(1000, function() use($cli) {
    debug_log("connect timeout");
    $cli->close();
    Assert::false($cli->isConnected());
});
