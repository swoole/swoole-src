--TEST--
swoole_http_client_coro: connection close
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\run;

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->get('/response-close'));
        Assert::false($client->connected);
        Assert::true($client->get('/response-next'));
        Assert::true($client->connected);
        $client->close();

        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->get('/response-token-close'));
        Assert::false($client->connected);

        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $client->setHeaders(['Connection' => 'close']);
        Assert::true($client->get('/request-close'));
        Assert::false($client->connected);
        $client->setHeaders([]);
        Assert::true($client->get('/request-next'));
        Assert::true($client->connected);
        $client->close();

        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $client->setHeaders(['Connection' => 'keep-alive, close']);
        Assert::true($client->get('/request-token-close'));
        Assert::false($client->connected);
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
        if (str_contains($data, '/response-token-close')) {
            $connection = "Connection: keep-alive, close\r\n";
        } elseif (str_contains($data, '/response-close')) {
            $connection = "Connection: close\r\n";
        } else {
            $connection = '';
        }
        $server->send($fd, "HTTP/1.1 200 OK\r\n{$connection}Content-Length: 0\r\n\r\n");
    });

    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
