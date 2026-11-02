--TEST--
swoole_http2_server: reject invalid trailer fields and TE without losing HPACK state
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_request_trailer.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS, 'coroutine'] as $mode) {
    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm) {
        try {
            foreach (['trailers', 'Trailers'] as $value) {
                $socket = http2_trailer_connect($pm->getFreePort());
                http2_trailer_send($socket, 1, 5, 1, http2_trailer_headers('/', 'GET') . http2_trailer_field('te', $value));
                Assert::same(http2_trailer_response($socket, 1)['body'], 'ok');
                fclose($socket);
            }
            foreach ([
                ['initial', 'te', 'gzip'],
                ['initial', 'te', 'trailers, gzip'],
                ['trailer', ':method', 'GET'],
                ['trailer', ':path', '/other'],
                ['trailer', 'te', 'gzip'],
                ['trailer', 'X-Upper', 'value'],
                ['trailer', 'x-invalid', "bad\r\nvalue"],
            ] as [$phase, $name, $value]) {
                $socket = http2_trailer_connect($pm->getFreePort());
                try {
                    $invalid = http2_trailer_field($name, $value)
                        // Must decode this field even though the previous one is invalid.
                        . http2_trailer_field('x-dynamic', 'retained', true);
                    if ($phase === 'initial') {
                        http2_trailer_send($socket, 1, 5, 1, http2_trailer_headers() . $invalid);
                    } else {
                        http2_trailer_send($socket, 1, 4, 1, http2_trailer_headers());
                        http2_trailer_send($socket, 0, 0, 1, 'body');
                        // Also exercise rejection across a continued trailer block.
                        http2_trailer_send($socket, 1, 1, 1, substr($invalid, 0, -3));
                        http2_trailer_send($socket, 9, 4, 1, substr($invalid, -3));
                    }
                    Assert::same(http2_trailer_response($socket, 1), ['reset' => SWOOLE_HTTP2_ERROR_PROTOCOL_ERROR]);
                    // Index 62 refers to the field inserted after the invalid field above.
                    http2_trailer_send($socket, 1, 5, 3, http2_trailer_headers('/', 'GET') . "\xbe");
                    Assert::same(http2_trailer_response($socket, 3)['body'], 'retained');
                } finally {
                    fclose($socket);
                }
            }
        } finally {
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        http2_trailer_server($pm, $mode, function ($request, $response) {
            $response->end($request->header['x-dynamic'] ?? 'ok');
        });
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
