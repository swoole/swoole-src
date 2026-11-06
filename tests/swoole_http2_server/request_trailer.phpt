--TEST--
swoole_http2_server: parse form bodies ending in trailers and isolate trailer fields
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--INI--
max_file_uploads=300
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_request_trailer.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS, 'coroutine'] as $mode) {
    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm) {
        $socket = http2_trailer_connect($pm->getFreePort());
        try {
            $id = 1;
            foreach ([false, true] as $trailers) {
                foreach ([0, 1, 200] as $files) {
                    if ($files === 0) {
                        $contentType = 'application/x-www-form-urlencoded';
                        $body = 'value=hello';
                    } else {
                        $contentType = 'multipart/form-data; boundary=test';
                        $body = "--test\r\nContent-Disposition: form-data; name=\"value\"\r\n\r\nhello\r\n";
                        for ($n = 0; $n < $files; ++$n) {
                            $body .= "--test\r\nContent-Disposition: form-data; name=\"file$n\"; filename=\"$n.txt\"\r\n\r\nfile$n\r\n";
                        }
                        $body .= "--test--\r\n";
                    }
                    $headers = http2_trailer_headers() . http2_trailer_field('content-type', $contentType)
                        . http2_trailer_field('cookie', 'token=initial');
                    http2_trailer_send($socket, 1, 4, $id, $headers);
                    $chunks = str_split($body, 4096);
                    foreach ($chunks as $index => $chunk) {
                        http2_trailer_send($socket, 0, !$trailers && $index === count($chunks) - 1 ? 1 : 0, $id, $chunk);
                    }
                    if ($trailers) {
                        http2_trailer_send($socket, 1, 5, $id,
                            http2_trailer_field('content-type', 'text/plain')
                            . http2_trailer_field('cookie', 'token=trailer')
                            . http2_trailer_field('x-checksum', 'one')
                            . http2_trailer_field('x-checksum', 'two'));
                    }
                    $result = json_decode(http2_trailer_response($socket, $id)['body'], true);
                    Assert::same($result['post'], ['value' => 'hello']);
                    Assert::same($result['files'], $files);
                    Assert::same($result['hash'], hash('sha256', $body));
                    Assert::same($result['contentType'], $contentType);
                    Assert::same($result['cookie'], 'initial');
                    $lastFiles = $result['paths'];
                    Assert::same($result['trailer'], $trailers ? [
                        'content-type' => 'text/plain', 'cookie' => 'token=trailer', 'x-checksum' => ['one', 'two'],
                    ] : null);
                    $id += 2;
                }
            }
            // The request and trailer array remain valid when the PHP handler retains the object.
            http2_trailer_send($socket, 1, 5, $id, http2_trailer_headers('/saved', 'GET'));
            Assert::same(json_decode(http2_trailer_response($socket, $id)['body'], true), [
                'content-type' => 'text/plain', 'cookie' => 'token=trailer', 'x-checksum' => ['one', 'two'],
            ]);
            $id += 2;
            // An empty trailer still completes the request and exposes an empty array.
            http2_trailer_send($socket, 1, 4, $id, http2_trailer_headers());
            http2_trailer_send($socket, 1, 5, $id);
            Assert::same(json_decode(http2_trailer_response($socket, $id)['body'], true)['trailer'], []);
            foreach ($lastFiles as $path) {
                Assert::false(file_exists($path));
            }
        } finally {
            fclose($socket);
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        $saved = null;
        http2_trailer_server($pm, $mode, function ($request, $response) use (&$saved) {
            if ($request->server['request_uri'] === '/saved') {
                $response->end(json_encode($saved->trailer));
                return;
            }
            $saved = $request;
            foreach ($request->files ?? [] as $file) {
                Assert::true(is_uploaded_file($file['tmp_name']));
            }
            $response->end(json_encode([
                'post' => $request->post,
                'files' => count($request->files ?? []),
                'paths' => array_column($request->files ?? [], 'tmp_name'),
                'hash' => hash('sha256', $request->rawContent()),
                'contentType' => $request->header['content-type'] ?? null,
                'cookie' => $request->cookie['token'] ?? null,
                'trailer' => $request->trailer,
            ]));
        });
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
