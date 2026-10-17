--TEST--
swoole_http_client_coro: host
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $client->setHeaders(['hOsT' => 'example.test']);
        Assert::true($client->get('/'));
        Assert::same(substr_count($client->body, "Host: example.test\r\n"), 1);
        Assert::notContains($client->body, "Host: 127.0.0.1");
        $client->close();

        $port = $pm->getFreePort();
        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $port);
        Assert::true($client->get('/'));
        Assert::contains($client->body, "Host: 127.0.0.1:{$port}\r\n");
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
    $server->on('receive', function (Swoole\Server $server, int $fd, int $reactorId, string $data) {
        $server->send($fd, "HTTP/1.1 200 OK\r\nContent-Length: " . strlen($data) . "\r\n\r\n{$data}");
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
