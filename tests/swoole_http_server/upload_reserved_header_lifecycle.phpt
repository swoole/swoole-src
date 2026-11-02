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

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    foreach ([false, true] as $guard) {
        $probe = tempnam(sys_get_temp_dir(), 'swoole-upload-probe-');
        $manifest = tempnam(sys_get_temp_dir(), 'swoole-upload-manifest-');
        file_put_contents($probe, 'keep this file');
        $pm = new ProcessManager;
        $pm->parentFunc = function () use ($pm, $probe) {
            Swoole\Coroutine\run(function () use ($pm, $probe) {
                $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
                $client->set(['timeout' => 5]);
                $client->setHeaders(['Content-Type' => 'multipart/form-data; boundary=b']);
                // The final small request reuses the connection after a legitimate preprocessed upload.
                foreach ([[32, true], [80000, true], [80000, false], [32, true]] as [$size, $spoof]) {
                    $content = str_repeat('x', $size);
                    $marker = $spoof ? "sWoOlE-uPlOaD-fIlE: $probe\r\n" : '';
                    $body = "--b\r\n$marker" . 'Content-Disposition: form-data; name="file"; filename="test.txt"'
                        . "\r\n$marker" . "Content-Type: text/plain\r\n\r\n$content\r\n--b--\r\n";
                    $sent = $client->post('/', $body);
                    if ($spoof && $size > 16384 && (!$sent || $client->statusCode === 400)) {
                        // Early rejection can reset the connection before the client finishes sending the body.
                        Assert::true(in_array($client->statusCode, [400, SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET], true));
                        Assert::same(file_get_contents($probe), 'keep this file');
                        $client->close();
                        continue;
                    }
                    Assert::true($sent);
                    Assert::same($client->statusCode, 200);
                    $result = json_decode($client->body, true);
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
