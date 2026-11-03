--TEST--
swoole_http2_server: discard trailers without changing initial headers, body parsing or HPACK state
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
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
            // A PRIORITY frame on an idle stream does not open that stream.
            http2_trailer_send($socket, 2, 0, 1, pack('NC', 0, 16));
            $multipart = "--test\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n"
                . "--test\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n"
                . "Content-Type: text/plain\r\n\r\nfile-data\r\n--test--\r\n";
            foreach ([false, true] as $fragmented) {
                foreach ([['application/x-www-form-urlencoded', 'field=value', null],
                    ['multipart/form-data; boundary=test', $multipart, 'file-data']] as [$type, $body, $file]) {
                    $headers = http2_trailer_headers('/original?initial=yes')
                        . http2_trailer_field('content-type', $type)
                        . http2_trailer_field('cookie', 'first=one')
                        . http2_trailer_field('cookie', 'second=two')
                        . http2_trailer_field('authorization', 'original')
                        . http2_trailer_field('x-check', 'initial')
                        . http2_trailer_field('content-length', (string) strlen($body))
                        . http2_trailer_field('content-length', (string) strlen($body))
                        . http2_trailer_field('accept-encoding', 'gzip')
                        . http2_trailer_field('accept-encoding', 'identity');
                    if ($fragmented) {
                        http2_trailer_send($socket, 1, 0, $id, substr($headers, 0, -3));
                        http2_trailer_send($socket, 9, 4, $id, substr($headers, -3));
                    } else {
                        http2_trailer_send($socket, 1, 4, $id, $headers);
                    }
                    http2_trailer_send($socket, 0, 0, $id, substr($body, 0, 5));
                    http2_trailer_send($socket, 0, 0, $id, substr($body, 5));
                    $trailers = '';
                    foreach ([':method' => 'PUT', ':path' => '/changed?extra=no', ':authority' => 'changed',
                        'content-type' => 'multipart/form-data', 'cookie' => 'extra=no',
                        'content-length' => '999999999999', 'accept-encoding' => 'gzip',
                        'host' => 'changed', 'authorization' => 'changed', 'x-check' => 'trailer'] as $name => $value) {
                        $trailers .= http2_trailer_field($name, $value);
                    }
                    // Even discarded fields must update the connection's dynamic HPACK table.
                    $trailers .= http2_trailer_field('x-dynamic', 'recorded', true);
                    if ($fragmented) {
                        http2_trailer_send($socket, 1, 1, $id, substr($trailers, 0, -3));
                        http2_trailer_send($socket, 9, 0, $id, substr($trailers, -3, 1));
                        http2_trailer_send($socket, 9, 4, $id, substr($trailers, -2));
                    } else {
                        // PADDED and PRIORITY bytes are framing, not part of the discarded header block.
                        http2_trailer_send($socket, 1, 1 | 4 | 8 | 32, $id,
                            "\x03" . pack('NC', 0, 16) . $trailers . "\0\0\0");
                    }
                    $result = json_decode(http2_trailer_response($socket, $id)['body'], true);
                    Assert::same($result['method'], 'POST');
                    Assert::same($result['uri'], '/original');
                    Assert::same($result['get'], ['initial' => 'yes']);
                    Assert::same($result['header']['content-type'], $type);
                    Assert::same($result['header']['host'], 'localhost');
                    Assert::same($result['header']['authorization'], 'original');
                    Assert::same($result['header']['x-check'], 'initial');
                    Assert::same($result['header']['accept-encoding'], 'identity');
                    Assert::same($result['header']['content-length'], (string) strlen($body));
                    Assert::false(isset($result['header']['cookie']));
                    Assert::false(isset($result['header']['x-dynamic']));
                    Assert::same($result['cookie'], ['first' => 'one', 'second' => 'two']);
                    Assert::same($result['post'], ['field' => 'value']);
                    Assert::same($result['file'], $file);
                    Assert::same($result['raw'], $body);
                    Assert::false($result['trailer_property']);
                    $id += 2;
                    // Index 62 references the field inserted by the discarded trailer above.
                    http2_trailer_send($socket, 1, 5, $id, http2_trailer_headers('/', 'GET') . "\xbe");
                    $result = json_decode(http2_trailer_response($socket, $id)['body'], true);
                    Assert::same($result['header']['x-dynamic'], 'recorded');
                    Assert::null($result['cookie']);
                    Assert::null($result['post']);
                    $id += 2;
                }
            }
            // Empty trailers also finish buffered form parsing.
            http2_trailer_send($socket, 1, 4, $id, http2_trailer_headers()
                . http2_trailer_field('content-type', 'application/x-www-form-urlencoded'));
            http2_trailer_send($socket, 0, 0, $id, 'field=value');
            http2_trailer_send($socket, 1, 5, $id);
            $result = json_decode(http2_trailer_response($socket, $id)['body'], true);
            Assert::same($result['post'], ['field' => 'value']);
        } finally {
            fclose($socket);
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        http2_trailer_server($pm, $mode, function ($request, $response) {
            $response->end(json_encode([
                'method' => $request->server['request_method'],
                'uri' => $request->server['request_uri'],
                'get' => $request->get,
                'header' => $request->header,
                'cookie' => $request->cookie,
                'post' => $request->post,
                'file' => isset($request->files['file']['tmp_name'])
                    ? file_get_contents($request->files['file']['tmp_name']) : null,
                'raw' => $request->rawContent(),
                'trailer_property' => property_exists($request, 'trailer'),
            ]));
        }, ['http_parse_files' => true]);
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
