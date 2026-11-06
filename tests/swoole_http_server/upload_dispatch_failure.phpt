--TEST--
swoole_http_server: reclaim preprocessed files when dispatch rejects concurrency
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm   = new ProcessManager();
    $gate = new Swoole\Atomic(0);
    $dir  = sys_get_temp_dir() . '/swoole-upload-dispatch-' . getmypid() . '-' . $mode;
    Assert::true(mkdir($dir));
    $pm->parentFunc = function () use ($pm, $gate, $dir) {
        $hold = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}");
        stream_set_timeout($hold, 3);
        fwrite($hold, "GET /hold HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        Assert::true($pm->wait());
        $body = "--review\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\r\n"
            . str_repeat('A', 80 * 1024) . "\r\n--review--\r\n";
        $head   = "POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: multipart/form-data; boundary=review\r\nContent-Length: " . strlen($body) . "\r\n\r\n";
        $socket = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}");
        stream_set_timeout($socket, 3);
        $data = $head . $body;
        for ($offset = 0; $offset < strlen($data);) {
            $written = fwrite($socket, substr($data, $offset));
            Assert::greaterThan($written, 0);
            $offset += $written;
        }
        $response = stream_get_contents($socket);
        fclose($socket);
        Assert::contains($response, '503 Service Unavailable');
        Assert::same(glob($dir . '/swoole.upfile.*'), []);
        $gate->set(1);
        Assert::contains(stream_get_contents($hold), 'HELD');
        fclose($hold);
        $pm->kill();
        Assert::true(rmdir($dir));
    };
    $pm->childFunc = function () use ($pm, $gate, $mode, $dir) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set(['worker_num' => 1, 'max_concurrency' => 1, 'log_file' => '/dev/null',
            'package_max_length'   => 65536, 'upload_max_filesize' => 1024 * 1024, 'upload_tmp_dir' => $dir]);
        $server->on('workerStart', function () use ($pm) { $pm->wakeup(); });
        $server->on('request', function ($request, $response) use ($pm, $gate) {
            if ($request->server['request_uri'] === '/hold') {
                $pm->wakeup();
                $deadline = microtime(true) + 5;
                while (!$gate->get() && microtime(true) < $deadline) {
                    Swoole\Coroutine::sleep(0.001);
                }
                $response->end('HELD');
            } else {
                $response->end('UNEXPECTED');
            }
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
?>
--EXPECT--
