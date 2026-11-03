--TEST--
swoole_http_server: only reactor-generated paths are trusted, including after keep-alive uploads
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip('requires Unix process support', PHP_OS_FAMILY === 'Windows');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function assert_reserved_upload_rejected(int $port, string $probe): void
{
    $socket = stream_socket_client("tcp://127.0.0.1:$port", $errno, $error, 3);
    Assert::notSame($socket, false);
    stream_set_timeout($socket, 3);
    try {
        $prefix = "--b\r\nsWoOlE-uPlOaD-fIlE: $probe\r\n"
            . 'Content-Disposition: form-data; name="file"; filename="test.txt"'
            . "\r\nContent-Type: text/plain\r\n\r\n";
        $length = strlen($prefix) + 80000 + strlen("\r\n--b--\r\n");
        $headers = "POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
            . "Content-Type: multipart/form-data; boundary=b\r\nContent-Length: $length\r\n"
            . "Expect: 100-continue\r\n\r\n";
        Assert::same(fwrite($socket, $headers), strlen($headers));
        $continue = '';
        while (($line = fgets($socket)) !== false) {
            $continue .= $line;
            if ($line === "\r\n") {
                break;
            }
        }
        Assert::true(str_starts_with($continue, "HTTP/1.1 100 Continue\r\n"));
        // Send only the part headers, so a reset during a large body write cannot hide the HTTP response.
        Assert::same(fwrite($socket, $prefix), strlen($prefix));
        $response = stream_get_contents($socket);
        Assert::false(stream_get_meta_data($socket)['timed_out']);
        Assert::true(str_starts_with($response, "HTTP/1.1 400 Bad Request\r\n"));
    } finally {
        fclose($socket);
    }
}

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    foreach ([false, true] as $guard) {
        $probe = tempnam(sys_get_temp_dir(), 'swoole-upload-probe-');
        $manifest = tempnam(sys_get_temp_dir(), 'swoole-upload-manifest-');
        file_put_contents($probe, 'keep this file');
        $pm = new ProcessManager;
        $pm->parentFunc = function () use ($pm, $probe, $manifest) {
            assert_reserved_upload_rejected($pm->getFreePort(), $probe);
            Assert::same(file_get_contents($manifest), '');
            Assert::same(file_get_contents($probe), 'keep this file');
            Swoole\Coroutine\run(function () use ($pm, $probe) {
                $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
                $client->set(['timeout' => 5]);
                $client->setHeaders(['Content-Type' => 'multipart/form-data; boundary=b']);
                $connection = null;
                // The final small request reuses the connection after a legitimate preprocessed upload.
                foreach ([[32, true], [80000, false], [32, true]] as [$size, $spoof]) {
                    $content = str_repeat('x', $size);
                    $marker = $spoof ? "sWoOlE-uPlOaD-fIlE: $probe\r\n" : '';
                    $body = "--b\r\n$marker" . 'Content-Disposition: form-data; name="file"; filename="test.txt"'
                        . "\r\n$marker" . "Content-Type: text/plain\r\n\r\n$content\r\n--b--\r\n";
                    Assert::true($client->post('/', $body));
                    Assert::same($client->statusCode, 200);
                    $result = json_decode($client->body, true);
                    if ($connection === null) {
                        $connection = $result['connection'];
                    } else {
                        Assert::same($result['connection'], $connection);
                    }
                    Assert::same($result['hash'], md5($content));
                    Assert::same($result['error'], UPLOAD_ERR_OK);
                    Assert::true($result['uploaded']);
                    Assert::false($result['probe_uploaded']);
                    Assert::false($result['path'] === $probe);
                    Assert::same(file_get_contents($probe), 'keep this file');
                }
                $client->close();
            });
            $pm->kill();
        };
        $pm->childFunc = function () use ($pm, $mode, $guard, $probe, $manifest) {
            $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
            $server->set([
                'worker_num' => 1,
                'log_file' => '/dev/null',
                'package_max_length' => 16384,
                'upload_max_filesize' => 262144,
            ]);
            $server->on('WorkerStart', function () use ($pm) { $pm->wakeup(); });
            $server->on('request', function ($request, $response) use ($guard, $probe, $manifest) {
                $file = $request->files['file'];
                $path = $file['tmp_name'];
                file_put_contents($manifest, $path . "\n", FILE_APPEND);
                $result = [
                    'connection' => [$request->fd, $request->server['remote_port'], getmypid()],
                    'hash' => md5_file($path),
                    'error' => $file['error'],
                    'path' => $path,
                    'uploaded' => is_uploaded_file($path),
                    'probe_uploaded' => is_uploaded_file($probe),
                ];
                if ($guard) {
                    $request->tmpfiles = [];
                }
                $response->end(json_encode($result));
            });
            $server->start();
        };
        try {
            $pm->childFirst();
            $pm->run();
            $pm->expectExitCode(0);
            clearstatcache();
            Assert::same(file_get_contents($probe), 'keep this file');
            foreach (file($manifest, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $path) {
                if (!$guard) {
                    Assert::false(file_exists($path));
                } elseif (is_file($path) && $path !== $probe) {
                    // Some worker exit paths bypass PHP shutdown. The separate process test covers SAPI cleanup.
                    unlink($path);
                }
            }
        } finally {
            unlink($probe);
            unlink($manifest);
        }
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
