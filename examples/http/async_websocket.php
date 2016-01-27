<?php
$cli = new swoole_http_client('127.0.0.1', 9501);

$cli->on('message', function ($_cli, $frame) {
    var_dump($frame);
});

$cli->upgrade('/', function ($cli) {
    echo $cli->body;
    $cli->push("hello world");
});
