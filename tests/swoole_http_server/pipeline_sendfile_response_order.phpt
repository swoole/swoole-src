--TEST--
swoole_http_server: preserve pipelined response order with sendfile
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $path = tempnam(sys_get_temp_dir(), 'swoole-pipeline-sendfile-');
    file_put_contents($path, 'first response');

    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm, $path) {
        $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort());
        stream_set_timeout($client, 2);
        fwrite(
            $client,
            "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n" .
            "GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n"
        );

        $response = '';
        while ((substr_count($response, 'HTTP/1.1 200 OK') < 2 ||
                !str_contains($response, 'first response') ||
                !str_contains($response, 'second response')) &&
               !feof($client)) {
            $data = fread($client, 8192);
            if (!$data) {
                break;
            }
            $response .= $data;
        }

        $firstBody = strpos($response, 'first response');
        $secondResponseStart = strpos($response, 'HTTP/1.1 200 OK', strlen('HTTP/1.1 200 OK'));
        Assert::true($firstBody !== false && $secondResponseStart !== false);
        Assert::true($firstBody < $secondResponseStart);

        clearstatcache(true, $path);
        Assert::false(is_file($path));

        fclose($client);
        $pm->kill();
        echo "DONE\n";
    };
    $pm->childFunc = function () use ($pm, $mode, $path) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'worker_num' => 1,
            'log_file' => '/dev/null',
        ]);
        $server->on('workerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($path) {
            if ($request->server['request_uri'] === '/first') {
                Swoole\Coroutine::sleep(0.05);
                Assert::true($response->sendfile($path, 0, 0, true));
            } else {
                $response->end('second response');
            }
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
    @unlink($path);
}
?>
--EXPECT--
DONE
DONE
