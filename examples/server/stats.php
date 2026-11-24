<?php
// Read live server statistics with Server::stats().
// Run: php examples/server/stats.php (press Ctrl+C to stop)
$server = new Swoole\Server('127.0.0.1', 9503);
$server->set(['worker_num' => 1]);
$server->on('receive', function ($server, $fd, $reactorId, $data) {
    $server->send($fd, 'ok' . PHP_EOL);
});
$server->on('workerStart', function ($server) {
    print_r($server->stats());
});
$server->start();
