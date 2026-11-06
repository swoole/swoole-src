--TEST--
swoole_http2_server: enforce continuation ordering, stream completion and header limits
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
            foreach (['orphan', 'different-stream', 'interleaved', 'duplicate'] as $case) {
                $socket = http2_trailer_connect($pm->getFreePort());
                try {
                    if ($case === 'orphan') {
                        http2_trailer_send($socket, 9, 4, 1, http2_trailer_headers());
                    } elseif ($case === 'duplicate') {
                        http2_trailer_send($socket, 1, 5, 1, http2_trailer_headers());
                        Assert::same(http2_trailer_response($socket, 1)['body'], 'ok');
                        http2_trailer_send($socket, 1, 5, 1, http2_trailer_headers());
                    } else {
                        http2_trailer_send($socket, 1, 0, 1, http2_trailer_headers());
                        if ($case === 'different-stream') {
                            http2_trailer_send($socket, 9, 4, 3);
                        } else {
                            http2_trailer_send($socket, 6, 0, 0, 'no-ack!!');
                        }
                    }
                    while (($frame = http2_test_read_frame($socket)) !== false) {
                        Assert::notSame($frame['type'], 0);
                        Assert::notSame($frame['type'], 1);
                        Assert::notSame($frame['type'], 6);
                    }
                    Assert::false(stream_get_meta_data($socket)['timed_out']);
                } finally {
                    fclose($socket);
                }
            }
            $socket = http2_trailer_connect($pm->getFreePort());
            // Six fields split across two frames must exceed the configured limit of five.
            http2_trailer_send($socket, 1, 1, 1, http2_trailer_headers() . http2_trailer_field('x-one', '1'));
            http2_trailer_send($socket, 9, 4, 1, http2_trailer_field('x-two', '2'));
            Assert::same(http2_trailer_response($socket, 1), ['reset' => SWOOLE_HTTP2_ERROR_ENHANCE_YOUR_CALM]);
            http2_trailer_send($socket, 1, 5, 3, http2_trailer_headers());
            Assert::same(http2_trailer_response($socket, 3)['body'], 'ok');
            fclose($socket);

            $socket = http2_trailer_connect($pm->getFreePort());
            http2_trailer_send($socket, 1, 4, 1, http2_trailer_headers());
            http2_trailer_send($socket, 1, 4, 1, http2_trailer_field('x-final', 'missing-end-stream'));
            Assert::same(http2_trailer_response($socket, 1), ['reset' => SWOOLE_HTTP2_ERROR_PROTOCOL_ERROR]);
            http2_trailer_send($socket, 1, 5, 3, http2_trailer_headers());
            Assert::same(http2_trailer_response($socket, 3)['body'], 'ok');
            fclose($socket);
        } finally {
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        http2_trailer_server($pm, $mode, function ($request, $response) {
            $response->end('ok');
        }, ['http2_max_headers' => 5]);
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
