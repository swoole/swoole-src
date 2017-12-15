<?php
$server = new Swoole\Http\Server("127.0.0.1", 9502, SWOOLE_BASE);

$server->set([
    'worker_num' => 1,
]);

$server->on('Request', function ($request, $response) {
    Swoole\Coroutine::sleep(0.2);
    $response->end('Test End');
});

$server->start();
