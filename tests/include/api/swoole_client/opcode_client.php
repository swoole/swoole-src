<?php


require_once __DIR__ . "/../../../include/bootstrap.php";



// suicide(5000);

$cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

/** @noinspection PhpVoidFunctionResultUsedInspection */
assert($cli->set([
    'open_length_check' => 1,
    'package_length_type' => 'N',
    'package_length_offset' => 0,
    'package_body_offset' => 0,
]));

$cli->on("connect", function(swoole_client $cli) {
    swoole_timer_clear($cli->timeo_id);
    assert($cli->isConnected() === true);

});

$cli->on("receive", function(swoole_client $cli, $data){

    $cli->close();
    assert($cli->isConnected() === false);
});

$cli->on("error", function(swoole_client $cli) {
    swoole_timer_clear($cli->timeo_id);
    echo "ERROR";
});

$cli->on("close", function(swoole_client $cli) {
    swoole_timer_clear($cli->timeo_id);
    echo "CLOSE";
});

$cli->connect(TCP_SERVER_HOST, TCP_SERVER_PORT);

$cli->timeo_id = swoole_timer_after(1000, function() use($cli) {
    debug_log("connect timeout");
    $cli->close();
    assert($cli->isConnected() === false);
});
