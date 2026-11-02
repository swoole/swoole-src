--TEST--
swoole_http2_server: trailers cannot bypass multipart completeness checks
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
                . http2_trailer_field('content-type', 'multipart/form-data; boundary=test');
            http2_trailer_send($socket, 1, 4, 1, $headers);
            http2_trailer_send($socket, 0, 0, 1,
                "--test\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\r\npartial");
            http2_trailer_send($socket, 1, 5, 1, http2_trailer_field('x-final', 'yes'));
            $result = http2_trailer_response($socket, 1);
            Assert::same(ord($result['headers'][0]), 0x8c); // HPACK static index 12: :status 400.
            http2_trailer_send($socket, 1, 5, 3, http2_trailer_headers('/health', 'GET'));
            Assert::same(http2_trailer_response($socket, 3)['body'], 'ok');
        } finally {
            fclose($socket);
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        http2_trailer_server($pm, $mode, function ($request, $response) {
            Assert::same($request->server['request_uri'], '/health');
            $response->end('ok');
        });
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
