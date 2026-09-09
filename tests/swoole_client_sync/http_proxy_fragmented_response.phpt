--TEST--
swoole_client_sync: fragmented HTTP proxy response
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $createClient = function (float $timeout = 0.5) use ($pm) {
        $client = new Swoole\Client(SWOOLE_SOCK_TCP);
        $client->set([
            'timeout' => $timeout,
            'http_proxy_host' => '127.0.0.1',
            'http_proxy_port' => $pm->getFreePort(),
        ]);
        return $client;
    };
    $connect = function () use ($createClient) {
        $client = $createClient();
        Assert::true($client->connect('example.com', 22));
        return $client;
    };

    $client = $connect();
    Assert::same($client->recv(), 'FRAGMENTED');
    $client->close();

    $client = $connect();
    Assert::same($client->recv(), 'SHORT');
    $client->close();

    $client = $connect();
    Assert::same($client->recv(), 'COMPLETE');
    $client->close();

    $client = $createClient();
    Assert::false(@$client->connect('example.com', 22));
    Assert::same($client->errCode, SWOOLE_ERROR_HTTP_PROXY_BAD_RESPONSE);

    $client = $createClient();
    Assert::false(@$client->connect('example.com', 22));
    Assert::same($client->errCode, SWOOLE_ERROR_HTTP_PROXY_BAD_RESPONSE);

    $client = $createClient(0.2);
    $started = microtime(true);
    Assert::false(@$client->connect('example.com', 22, 0.2));
    Assert::greaterThan(microtime(true) - $started, 0.1);
    Assert::lessThan(microtime(true) - $started, 0.45);
    Assert::same($client->errCode, SWOOLE_ERROR_HTTP_PROXY_HANDSHAKE_FAILED);

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $server = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort());
    $pm->wakeup();

    $responses = [
        [["HTTP/1.1 200 ", "Connection established\r\nProxy-Agent: test\r\n\r\nFRAGMENTED"], 20000],
        [["HTTP/1.1 200 OK\r\n\r\nSHORT"], 20000],
        [["HTTP/1.1 200 Connection established\r\n", "\r\nCOMPLETE"], 20000],
        [["HTTP/1.1 407 Proxy Authentication Required\r\n"], 20000],
        [["HTTP/1.1 200 Connection"], 20000],
        [["HTTP/1.1", " 200", " OK\r\n\r\n"], 150000],
    ];

    foreach ($responses as [$chunks, $delay]) {
        $connection = stream_socket_accept($server);
        $request = '';
        while (!str_contains($request, "\r\n\r\n")) {
            $request .= fread($connection, 8192);
        }
        foreach ($chunks as $chunk) {
            @fwrite($connection, $chunk);
            usleep($delay);
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
