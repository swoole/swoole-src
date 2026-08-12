--TEST--
swoole_http_client_coro: preserved Content-Type casing selects event stream completion
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $client->set([
            'lowercase_header' => false,
            'timeout' => 2,
        ]);
        Assert::true($client->get('/'));
        Assert::same($client->body, "data: hello\n\n");
        Assert::keyExists($client->getHeaders(), 'Content-Type');
        $client->close();
        echo "DONE\n";
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('receive', function (Swoole\Server $server, int $fd) {
        // Keep the connection open so only event-stream recognition can complete the response.
        $server->send($fd, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: hello\n\n");
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
