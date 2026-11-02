--TEST--
swoole_http2_server: initialize body parsing from the last Content-Type after END_HEADERS
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_request_trailer.php';

$formType = 'application/x-www-form-urlencoded';
$multipartType = 'multipart/form-data; boundary=test';
$multipart = "--test\r\nContent-Disposition: form-data; name=\"value\"\r\n\r\nhello\r\n" .
    "--test\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\r\nfile-data\r\n--test--\r\n";
$post = ['value' => 'hello'];
$cases = [
    [['multipart/form-data', $formType], 'value=hello', $post, 0],
    [['multipart/form-data; boundary=""', $multipartType], $multipart, $post, 1],
    [[$multipartType, 'multipart/form-data', $formType], 'value=hello', $post, 0],
    [[$formType, $multipartType], $multipart, $post, 1],
    [['multipart/form-data; boundary=old', $multipartType], $multipart, $post, 1],
    [['multipart/form-data', 'text/plain'], 'raw', null, 0],
    [[$formType, ''], 'value=hello', null, 0],
    [[$multipartType, $multipartType, $multipartType], $multipart, $post, 1],
];

foreach ([SWOOLE_BASE, SWOOLE_PROCESS, 'coroutine'] as $mode) {
    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm, $cases, $multipartType) {
        $socket = null;
        try {
            $socket = http2_trailer_connect($pm->getFreePort());
            $id = 1;
            foreach ([false, true] as $fragmented) {
                foreach ([false, true] as $trailers) {
                    foreach ($cases as [$types, $body, $post, $files]) {
                        $lastType = end($types);
                        $lastField = http2_trailer_field('content-type', array_pop($types));
                        $headers = http2_trailer_headers();
                        foreach ($types as $type) {
                            $headers .= http2_trailer_field('content-type', $type);
                        }
                        if ($fragmented) {
                            // The earlier values are complete, but the final field crosses CONTINUATION frames.
                            http2_trailer_send($socket, 1, 0, $id, $headers);
                            $split = intdiv(strlen($lastField), 2);
                            http2_trailer_send($socket, 9, 0, $id, substr($lastField, 0, $split));
                            http2_trailer_send($socket, 9, 4, $id, substr($lastField, $split));
                        } else {
                            http2_trailer_send($socket, 1, 4, $id, $headers . $lastField);
                        }
                        http2_trailer_send($socket, 0, 0, $id, substr($body, 0, 5));
                        http2_trailer_send($socket, 0, $trailers ? 0 : 1, $id, substr($body, 5));
                        if ($trailers) {
                            // This invalid multipart value is opaque trailer data, not a replacement Content-Type.
                            http2_trailer_send($socket, 1, 5, $id,
                                http2_trailer_field('content-type', 'multipart/form-data'));
                        }
                        $result = json_decode(http2_trailer_response($socket, $id)['body'], true);
                        Assert::same($result['contentType'], $lastType);
                        Assert::same($result['post'], $post);
                        Assert::same($result['files'], $files);
                        Assert::same($result['file'], $files ? 'file-data' : null);
                        Assert::same($result['hash'], hash('sha256', $body));
                        Assert::same($result['trailer'], $trailers ? ['content-type' => 'multipart/form-data'] : null);
                        $id += 2;
                    }
                }
            }
            // END_STREAM on the initial HEADERS still configures the final value before dispatch.
            foreach ([['multipart/form-data', 'text/plain'], ['multipart/form-data', $multipartType], []] as $types) {
                $headers = http2_trailer_headers();
                foreach ($types as $type) {
                    $headers .= http2_trailer_field('content-type', $type);
                }
                http2_trailer_send($socket, 1, 5, $id, $headers);
                $result = json_decode(http2_trailer_response($socket, $id)['body'], true);
                Assert::same($result['contentType'], $types ? end($types) : null);
                Assert::null($result['post']);
                Assert::same($result['files'], 0);
                $id += 2;
            }
            fclose($socket);
            // A malformed final value must still be rejected before the application handles the request.
            $socket = http2_trailer_connect($pm->getFreePort());
            http2_trailer_send($socket, 1, 5, 1, http2_trailer_headers()
                . http2_trailer_field('content-type', 'application/x-www-form-urlencoded')
                . http2_trailer_field('content-type', 'multipart/form-data'));
            while (($frame = http2_test_read_frame($socket)) !== false) {
                Assert::false($frame['streamId'] === 1 && in_array($frame['type'], [0, 1], true));
            }
            Assert::false(stream_get_meta_data($socket)['timed_out']);
        } finally {
            if (is_resource($socket)) {
                fclose($socket);
            }
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        http2_trailer_server($pm, $mode, function ($request, $response) {
            $response->end(json_encode([
                'contentType' => $request->header['content-type'] ?? null,
                'post' => $request->post,
                'files' => count($request->files ?? []),
                'file' => isset($request->files['file']['tmp_name'])
                    ? file_get_contents($request->files['file']['tmp_name']) : null,
                'hash' => hash('sha256', $request->rawContent()),
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
