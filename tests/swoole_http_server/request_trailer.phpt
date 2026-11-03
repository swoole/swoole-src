--TEST--
swoole_http_server: ignore HTTP/1 trailers without changing headers or body parsing
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS, 'coroutine'] as $mode) {
    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm) {
        try {
            $multipart = "--test\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n" .
                "--test\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n" .
                "Content-Type: text/plain\r\n\r\nfile-data\r\n--test--\r\n";
            foreach ([['multipart/form-data; boundary=test', $multipart],
                ['application/x-www-form-urlencoded', 'field=value']] as [$type, $body]) {
                $socket = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort());
                stream_set_timeout($socket, 3);
                $request = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: $type\r\n" .
                    "Cookie: initial=yes\r\nX-Check: header\r\nTransfer-Encoding: chunked\r\n\r\n";
                foreach (str_split($body, 17) as $chunk) {
                    $request .= dechex(strlen($chunk)) . "\r\n$chunk\r\n";
                }
                $request .= "0\r\nContent-Type: text/plain\r\nCookie: extra=no\r\nUpgrade: websocket\r\nAccept-Encoding: gzip\r\n" .
                    "X-Check: first\r\nx-check: second\r\nX-Empty:\r\n\r\n";
                // A second request on the same connection must have no inherited trailers.
                $next = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
                Assert::same(fwrite($socket, $request . $next), strlen($request . $next));
                $raw = stream_get_contents($socket);
                Assert::false(stream_get_meta_data($socket)['timed_out']);
                fclose($socket);
                Assert::same(substr_count($raw, 'HTTP/1.1 200 OK'), 2);
                $responses = explode('HTTP/1.1 200 OK', $raw);
                $result = json_decode(explode("\r\n\r\n", $responses[1], 2)[1], true);
                Assert::false($result['trailer']);
                Assert::same($result['header']['content-type'], $type);
                Assert::same($result['header']['x-check'], 'header');
                Assert::false(isset($result['header']['x-empty']));
                Assert::false(isset($result['header']['upgrade']));
                Assert::false(isset($result['header']['accept-encoding']));
                Assert::same($result['cookie'], ['initial' => 'yes']);
                Assert::same($result['post'], ['field' => 'value']);
                Assert::same($result['raw'], $body);
                Assert::same($result['file'], $type === 'multipart/form-data; boundary=test' ? 'file-data' : null);
                $result = json_decode(explode("\r\n\r\n", $responses[2], 2)[1], true);
                Assert::false($result['trailer']);
                Assert::null($result['post']);
                Assert::null($result['file']);
            }
        } finally {
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        $handler = function ($request, $response) {
            $response->end(json_encode([
                'trailer' => property_exists($request, 'trailer'),
                'header' => $request->header,
                'cookie' => $request->cookie,
                'post' => $request->post,
                'file' => isset($request->files['file']['tmp_name'])
                    ? file_get_contents($request->files['file']['tmp_name']) : null,
                'raw' => $request->rawContent(),
            ]));
        };
        if ($mode === 'coroutine') {
            Swoole\Coroutine\run(function () use ($pm, $handler) {
                $server = new Swoole\Coroutine\Http\Server('127.0.0.1', $pm->getFreePort());
                $server->set(['http_parse_files' => true, 'http_compression' => false]);
                $server->handle('/', $handler);
                $pm->wakeup();
                $server->start();
            });
            return;
        }
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set(['worker_num' => 1, 'reactor_num' => 1, 'http_parse_files' => true,
            'http_compression' => false, 'log_file' => '/dev/null']);
        $server->on('WorkerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $server->on('Request', $handler);
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
