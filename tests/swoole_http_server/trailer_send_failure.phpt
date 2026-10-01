--TEST--
swoole_http_server: trailer send failure
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort());
    fwrite($client, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream_get_contents($client);
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'log_file' => '/dev/null',
        'output_buffer_size' => 256,
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        Assert::true($response->trailer('x-test', str_repeat('a', 256)));
        Assert::true($response->write('body'));
        var_dump($response->end());
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
bool(false)
