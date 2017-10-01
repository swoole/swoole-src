<?php

// Cannot destroy active lambda swoole_function
// 先用nc起一个 swoole_server
// nc -4lk 9090

send("hello", function($cli, $data) {
    var_dump($data);
    send("hello", function($cli, $data) {
        var_dump($data);
        send("hello", function($cli, $data) {
            var_dump($data);
        });
    });
});



function send($str, $onRecv)
{
    static $client;

    if ($client === null) {
        $client = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

        $client->on("error", function($cli) { echo "error"; });
        $client->on("close", function($cli) { echo "close"; });

        $client->on("connect", function($cli) use($str, $onRecv) {
            send($str, $onRecv);
        });
    }

    // !!! Fatal error: Cannot destroy active lambda swoole_function
    $client->on("receive", $onRecv);

    if ($client->isConnected()) {
        $client->send("PING");
    } else {
        $client->connect("127.0.0.1", 9090);
    }
}
