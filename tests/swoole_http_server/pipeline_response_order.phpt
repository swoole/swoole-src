--TEST--
swoole_http_server: preserve pipelined response order
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
        fwrite(
            $client,
            "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n" .
            "POST /body HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ndata" .
            "GET /last HTTP/1.1\r\nHost: localhost\r\n\r\n"
        );

        $response = '';
        while ((substr_count($response, 'HTTP/1.1 200 OK') < 3 || substr_count($response, "0\r\n\r\n") < 2 ||
                !str_contains($response, 'last')) &&
               !feof($client)) {
            $data = fread($client, 8192);
            if (!$data) {
                break;
            }
            $response .= $data;
        }

        $firstResponseEnd = strpos($response, "0\r\n\r\n");
        $secondResponseStart = strpos($response, 'HTTP/1.1 200 OK', strlen('HTTP/1.1 200 OK'));
        $secondResponseEnd = strpos($response, "0\r\n\r\n", $firstResponseEnd + strlen("0\r\n\r\n"));
        $thirdResponseStart = strpos($response, 'HTTP/1.1 200 OK', $secondResponseStart + strlen('HTTP/1.1 200 OK'));
        Assert::true(
            $firstResponseEnd !== false && $secondResponseStart !== false && $secondResponseEnd !== false &&
            $thirdResponseStart !== false
        );
        Assert::true($firstResponseEnd < $secondResponseStart);
        Assert::true($secondResponseEnd < $thirdResponseStart);
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
        $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
            $uri = $request->server['request_uri'];
            if ($uri === '/first' || $uri === '/body') {
                $response->write(substr($uri, 1));
                Swoole\Coroutine::sleep(0.05);
                $response->end();
            } else {
                $response->end('last');
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
