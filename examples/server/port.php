<?php
// One server can listen on several ports, each with its own protocol.
// Run: php examples/server/port.php (press Ctrl+C to stop)
$server = new Swoole\Server('127.0.0.1', 9506);
$server->on('receive', function ($server, $fd, $reactorId, $data) {
    $server->send($fd, 'tcp echo: ' . $data);
});

$udp = $server->listen('127.0.0.1', 9507, SWOOLE_SOCK_UDP);
$udp->on('packet', function ($server, $data, $addr) {
    $server->sendto($addr['address'], $addr['port'], 'udp echo: ' . $data);
});
$server->start();
