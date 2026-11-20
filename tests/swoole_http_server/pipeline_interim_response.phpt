--TEST--
swoole_http_server: an interim response sent with Server::send() does not release the next pipelined request
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm) {
        $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort());
        stream_set_timeout($client, 2);
        fwrite($client, "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\nGET /second HTTP/1.1\r\nHost: localhost\r\n\r\n");
        $response = '';
        while (!str_contains($response, 'second') && ($data = fread($client, 8192))) {
            $response .= $data;
        }
        $interim = strpos($response, '103 Early Hints');
        $first = strpos($response, 'first');
        $second = strpos($response, 'second');
        Assert::true($interim !== false && $first !== false && $second !== false);
        Assert::true($interim < $first && $first < $second);
        fclose($client);
        $pm->kill();
        echo "DONE\n";
    };
    $pm->childFunc = function () use ($pm, $mode) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'worker_num' => 1,
            'log_file' => '/dev/null',
        ]);
        $server->on('workerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($server) {
            if ($request->server['request_uri'] === '/first') {
                $server->send($request->fd, "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n");
                Swoole\Coroutine::sleep(0.05);
                $response->end('first');
            } else {
                $response->end('second');
            }
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
?>
--EXPECT--
DONE
DONE
