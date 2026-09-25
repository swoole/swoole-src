--TEST--
swoole_client_coro: preserve data after the HTTP proxy response
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $createClient = function (float $timeout = 5) use ($pm) {
            $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
            $client->set([
                'timeout' => $timeout,
                'http_proxy_host' => '127.0.0.1',
                'http_proxy_port' => $pm->getFreePort(),
            ]);
            return $client;
        };

        $client = $createClient();
        Assert::true($client->connect('example.com', 22));
        Assert::same($client->recv(), 'TUNNEL DATA');
        $client->close();

        $client = $createClient();
        $started = microtime(true);
        Assert::false($client->connect('example.com', 22));
        Assert::lessThan(microtime(true) - $started, 1);
        Assert::same($client->errCode, SWOOLE_ERROR_HTTP_PROXY_BAD_RESPONSE);

        $client = $createClient();
        Assert::false($client->connect('example.com', 22));
        Assert::same($client->errCode, SWOOLE_ERROR_HTTP_PROXY_BAD_RESPONSE);

        $client = $createClient(0.2);
        $started = microtime(true);
        Assert::false($client->connect('example.com', 22));
        Assert::greaterThan(microtime(true) - $started, 0.1);
        Assert::lessThan(microtime(true) - $started, 0.45);
        Assert::same($client->errCode, SWOOLE_ERROR_HTTP_PROXY_HANDSHAKE_FAILED);

        $client = $createClient();
        $started = microtime(true);
        Assert::false($client->connect('example.com', 22));
        Assert::lessThan(microtime(true) - $started, 1);
        Assert::same($client->errCode, SWOOLE_ERROR_HTTP_PROXY_BAD_RESPONSE);

        $pm->kill();
        echo "DONE\n";
    });
};

$pm->childFunc = function () use ($pm) {
    $server = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort());
    $pm->wakeup();
    $responses = [
        [["HTTP/1.1 200 Connection established\r\n", "\r\nTUNNEL DATA"], 20000, 0],
        [["HTTP/1.1 407 Proxy Authentication Required\r\n"], 20000, 1500000],
        [["HTTP/1.1 200 Connection"], 20000, 0],
        [["HTTP/1.1", " 200", " OK\r\n\r\n"], 150000, 0],
        [["not-http"], 20000, 1500000],
    ];

    foreach ($responses as [$chunks, $delay, $closeDelay]) {
        $connection = stream_socket_accept($server);
        $request = '';
        while (!str_contains($request, "\r\n\r\n")) {
            $request .= fread($connection, 8192);
        }
        foreach ($chunks as $chunk) {
            @fwrite($connection, $chunk);
            usleep($delay);
        }
        if ($closeDelay > 0) {
            usleep($closeDelay);
        }
        fclose($connection);
    }
    fclose($server);
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
