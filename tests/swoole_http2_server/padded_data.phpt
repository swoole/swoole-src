--TEST--
swoole_http2_server: discard the padding of request DATA frames
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_request_trailer.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS, 'coroutine'] as $mode) {
    $pm             = new ProcessManager();
    $pm->parentFunc = function () use ($pm) {
        $socket = http2_trailer_connect($pm->getFreePort());
        try {
            // PADDED DATA frames, the last one all padding
            http2_trailer_send($socket, 1, 4, 1, http2_trailer_headers());
            http2_trailer_send($socket, 0, 8, 1, "\x03value=\0\0\0");
            http2_trailer_send($socket, 0, 8, 1, "\x00hello");
            http2_trailer_send($socket, 0, 9, 1, "\x02\0\0");
            Assert::same(http2_trailer_response($socket, 1)['body'], 'value=hello');

            // Padding at least as long as the payload closes the connection
            http2_trailer_send($socket, 1, 4, 3, http2_trailer_headers());
            http2_trailer_send($socket, 0, 9, 3, "\x04abc");
            while (http2_test_read_frame($socket) !== false) {
            }
            Assert::true(feof($socket));
        } finally {
            fclose($socket);
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        http2_trailer_server($pm, $mode, function ($request, $response) {
            $response->end($request->rawContent());
        });
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
