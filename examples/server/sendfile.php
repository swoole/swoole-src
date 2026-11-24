<?php
// Send a file to every connected client.
$serv = new Swoole\Server('0.0.0.0', 9501, SWOOLE_BASE);
$serv->set([
    'worker_num' => 1,
]);
$serv->on('connect', function (Swoole\Server $serv, $fd) {
    $serv->send($fd, filesize(__DIR__ . '/test.jpg'));
});
$serv->on('receive', function (Swoole\Server $serv, $fd, $reactor_id, $data) {
    echo "Client[$fd]: $data" . PHP_EOL;
    $serv->sendfile($fd, __DIR__ . '/test.jpg');
});
$serv->start();
