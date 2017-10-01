<?php

require_once __DIR__ . "/../../../include/bootstrap.php";

$cli = new \swoole_http_client("127.0.0.1", 65535);

$cli->on('close', function($cli) {
    echo 'close\n';
});

$cli->on('error', function($cli) {
    echo "error\n";
});

swoole_timer_after(500, function() {
    swoole_event_exit();
    echo "time out\n";
});
$cli->get('/', function(swoole_http_client $cli) {});