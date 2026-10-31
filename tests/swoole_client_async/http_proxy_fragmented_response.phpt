--TEST--
swoole_client_async: fragmented HTTP proxy response
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $completed = 0;
    $finish = function () use (&$completed, $pm) {
        if (++$completed === 3) {
            $pm->kill();
            echo "DONE\n";
        }
    };
    $connect = function (string $host, bool $shouldSucceed) use ($finish, $pm) {
        $client = new Swoole\Async\Client(SWOOLE_SOCK_TCP);
        $client->set([
            'http_proxy_host' => '127.0.0.1',
            'http_proxy_port' => $pm->getFreePort(),
        ]);
        $client->on('connect', function () use ($shouldSucceed) {
            Assert::true($shouldSucceed);
        });
        $client->on('receive', function (Swoole\Async\Client $client, string $data) use ($finish, $shouldSucceed) {
            Assert::true($shouldSucceed);
            Assert::same($data, 'TUNNEL DATA');
            $client->close();
            $finish();
        });
        $client->on('error', function (Swoole\Async\Client $client) use ($finish, $shouldSucceed) {
            Assert::false($shouldSucceed);
            Assert::same($client->errCode, SWOOLE_ERROR_HTTP_PROXY_BAD_RESPONSE);
            $finish();
        });
        $client->on('close', function () {});
        Assert::true($client->connect($host, 22, 0.5));
    };

    $connect('success.example.com', true);
    $connect('invalid.example.com', false);
    $connect('eof.example.com', false);
};

$pm->childFunc = function () use ($pm) {
    $server = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort());
    $pm->wakeup();
    for ($i = 0; $i < 3; $i++) {
        $connection = stream_socket_accept($server);
        $request = '';
        while (!str_contains($request, "\r\n\r\n")) {
            $request .= fread($connection, 8192);
        }
        if (str_contains($request, 'success.example.com')) {
            fwrite($connection, "HTTP/1.1 200 ");
            usleep(20000);
            fwrite($connection, "Connection established\r\n\r\nTUNNEL DATA");
            usleep(100000);
        } elseif (str_contains($request, 'invalid.example.com')) {
            fwrite($connection, "HTTP/1.1 407 Proxy Authentication Required\r\n");
        } else {
            fwrite($connection, "HTTP/1.1 200 Connection");
        }
        fclose($connection);
    }
    fclose($server);
};

$pm->async = true;
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
