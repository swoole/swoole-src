--TEST--
swoole_http2_server: complete request headers and trailers across CONTINUATION frames
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
            $headers = http2_trailer_headers()
                . http2_trailer_field('content-type', 'application/x-www-form-urlencoded');
            // Split the final field, not just the sequence of complete fields.
            http2_trailer_send($socket, 1, 0, 1, substr($headers, 0, -5));
            http2_trailer_send($socket, 9, 4, 1, substr($headers, -5));
            http2_trailer_send($socket, 0, 0, 1, 'value=hello');
            $trailer = http2_trailer_field('x-one', 'one') . http2_trailer_field('x-two', 'second');
            http2_trailer_send($socket, 1, 1, 1, substr($trailer, 0, -3));
            http2_trailer_send($socket, 9, 0, 1, substr($trailer, -3, 1));
            http2_trailer_send($socket, 9, 4, 1, substr($trailer, -2));
            $response = json_decode(http2_trailer_response($socket, 1)['body'], true);
            Assert::same($response, ['post' => ['value' => 'hello'], 'trailer' => ['x-one' => 'one', 'x-two' => 'second']]);

            // END_STREAM on initial HEADERS must also wait for END_HEADERS.
            $headers = http2_trailer_headers('/empty', 'GET');
            http2_trailer_send($socket, 1, 1, 3, substr($headers, 0, -2));
            http2_trailer_send($socket, 9, 4, 3, substr($headers, -2));
            $response = json_decode(http2_trailer_response($socket, 3)['body'], true);
            Assert::same($response, ['post' => null, 'trailer' => null]);
        } finally {
            fclose($socket);
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        http2_trailer_server($pm, $mode, function ($request, $response) {
            $response->end(json_encode(['post' => $request->post, 'trailer' => $request->trailer]));
        });
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
