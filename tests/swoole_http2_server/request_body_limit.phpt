--TEST--
swoole_http2_server: reset only the stream whose request is over package_max_length or refused
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_request_trailer.php';

// Collects frames by stream until stream $id ends.
function http2_body_limit_read($socket, int $id): array
{
    $frames = [];
    while (($frame = http2_test_read_frame($socket)) !== false) {
        Assert::notSame($frame['type'], 7);
        if ($frame['type'] === 4 && ($frame['flags'] & 1) === 0) {
            http2_trailer_send($socket, 4, 1, 0);
        }
        $frames[$frame['streamId']][] = $frame;
        if ($frame['streamId'] === $id && ($frame['type'] === 0 || $frame['type'] === 1) && ($frame['flags'] & 1)) {
            return $frames;
        }
    }
    throw new RuntimeException('Incomplete HTTP/2 response');
}

function http2_body_limit_assert_rejected(array $frames): void
{
    Assert::same(count($frames), 2);
    Assert::same([$frames[0]['type'], $frames[0]['flags']], [1, 5]);
    Assert::same(substr($frames[0]['payload'], 0, 5), "\x48\x03413");
    Assert::same([$frames[1]['type'], $frames[1]['payload']], [3, pack('N', SWOOLE_HTTP2_ERROR_NO_ERROR)]);
}

function http2_body_limit_response(array $frames): array
{
    $body = '';
    foreach ($frames as $frame) {
        if ($frame['type'] === 0) {
            $body .= $frame['payload'];
        }
    }
    return json_decode($body, true);
}

foreach ([SWOOLE_BASE, SWOOLE_PROCESS, 'coroutine'] as $mode) {
    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm) {
        $data = str_repeat('a', 16383);
        try {
            // A body over the limit, sent within the advertised flow-control credit and ending with trailers.
            $socket = http2_trailer_connect($pm->getFreePort());
            $credit = 65535;
            http2_trailer_send($socket, 1, 4, 1, http2_trailer_headers('/rejected-body'));
            for ($i = 0; $i < 4; $i++) {
                http2_trailer_send($socket, 0, 0, 1, $data);
                $credit -= strlen($data);
            }
            for ($updated = []; count($updated) < 2;) {
                $frame = http2_test_read_frame($socket);
                Assert::notSame($frame, false);
                if ($frame['type'] === 4 && ($frame['flags'] & 1) === 0) {
                    http2_trailer_send($socket, 4, 1, 0);
                } elseif ($frame['type'] === 8) {
                    $updated[$frame['streamId']] = true;
                    if ($frame['streamId'] === 0) {
                        $credit += unpack('N', $frame['payload'])[1];
                    }
                }
            }
            for ($i = 0; $i < 4; $i++) {
                http2_trailer_send($socket, 0, 0, 1, $data);
                $credit -= strlen($data);
            }
            // The trailer block continues in CONTINUATION after the stream is reset; its indexed field must still
            // reach the HPACK table.
            $trailer = http2_trailer_field('x-indexed', 'trailer', true);
            http2_trailer_send($socket, 1, 1, 1, substr($trailer, 0, -3));
            http2_trailer_send($socket, 9, 4, 1, substr($trailer, -3));
            http2_trailer_send($socket, 1, 5, 3, http2_trailer_headers('/after-body', 'GET') . "\xbe");
            $frames = http2_body_limit_read($socket, 3);
            http2_body_limit_assert_rejected($frames[1]);
            Assert::same(http2_body_limit_response($frames[3]), ['trailer', ['/after-body']]);
            foreach ($frames[0] ?? [] as $frame) {
                if ($frame['type'] === 8) {
                    $credit += unpack('N', $frame['payload'])[1];
                }
            }
            Assert::greaterThanEq($credit, 16384);
            fclose($socket);

            // A content-length over the limit, then a repeated one and an indexed field in CONTINUATION.
            $socket = http2_trailer_connect($pm->getFreePort());
            $length = http2_trailer_field('content-length', '131072');
            http2_trailer_send($socket, 1, 0, 1, http2_trailer_headers('/rejected-length') . $length);
            http2_trailer_send($socket, 9, 4, 1, $length . http2_trailer_field('x-indexed', 'length', true));
            http2_trailer_send($socket, 0, 0, 1, $data);
            http2_trailer_send($socket, 0, 0, 1, $data);
            http2_trailer_send($socket, 1, 5, 3, http2_trailer_headers('/after-length', 'GET') . "\xbe");
            $frames = http2_body_limit_read($socket, 3);
            http2_body_limit_assert_rejected($frames[1]);
            Assert::same(http2_body_limit_response($frames[3]), ['length', ['/after-body', '/after-length']]);
            fclose($socket);

            // An upload refused by max_concurrent_streams while another request is running.
            $socket = http2_trailer_connect($pm->getFreePort());
            http2_trailer_send($socket, 1, 5, 1, http2_trailer_headers('/slow', 'GET'));
            http2_trailer_send($socket, 1, 4, 3, http2_trailer_headers('/refused'));
            http2_trailer_send($socket, 0, 0, 3, $data);
            http2_trailer_send($socket, 0, 1, 3, $data);
            $frames = http2_body_limit_read($socket, 1);
            Assert::same(count($frames[3]), 1);
            $reset = [3, pack('N', SWOOLE_HTTP2_ERROR_REFUSED_STREAM)];
            Assert::same([$frames[3][0]['type'], $frames[3][0]['payload']], $reset);
            Assert::same(http2_body_limit_response($frames[1]), [null, ['/after-body', '/after-length', '/slow']]);
            fclose($socket);
        } finally {
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        $paths = [];
        http2_trailer_server($pm, $mode, function ($request, $response) use (&$paths) {
            $paths[] = $request->server['request_uri'];
            if ($request->server['request_uri'] === '/slow') {
                Swoole\Coroutine::sleep(0.1);
            }
            $response->end(json_encode([$request->header['x-indexed'] ?? null, $paths]));
        }, ['package_max_length' => 64 * 1024, 'http2_max_concurrent_streams' => 1]);
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
