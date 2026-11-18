--TEST--
swoole_http2_server: fit each DATA frame and its header within output_buffer_size
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

const HTTP2_FLAG_END_STREAM = 0x1;
const HTTP2_SETTINGS_INIT_WINDOW_SIZE = 0x4;
const HTTP2_SETTINGS_MAX_FRAME_SIZE = 0x5;

// The write fills one frame at the peer's limit, which is also the worker's limit on one send
foreach ([16384, 65536] as $size) {
    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm, $size) {
        $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort(), $errno, $errstr, 2);
        Assert::notEmpty($client);
        stream_set_timeout($client, 2);
        $settings = pack('nN', HTTP2_SETTINGS_INIT_WINDOW_SIZE, 0x7fffffff);
        if ($size !== 16384) {
            $settings .= pack('nN', HTTP2_SETTINGS_MAX_FRAME_SIZE, $size);
        }
        $request = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            . http2_test_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0, $settings)
            . http2_test_frame(SWOOLE_HTTP2_TYPE_WINDOW_UPDATE, 0, 0, pack('N', 0x7fff0000))
            . http2_test_request_headers(1, '/');
        Assert::same(fwrite($client, $request), strlen($request));

        $body = '';
        do {
            $frame = http2_test_wait_for_frame($client, SWOOLE_HTTP2_TYPE_DATA);
            $body .= $frame['payload'];
        } while (!($frame['flags'] & HTTP2_FLAG_END_STREAM));
        fclose($client);
        Assert::true($body === str_repeat('a', $size) . 'true');
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $size) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
        $server->set([
            'output_buffer_size' => $size,
            'worker_num' => 1,
            'open_http2_protocol' => true,
            'http_compression' => false,
            'log_file' => '/dev/null',
        ]);
        $server->on('WorkerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $server->on('Request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($size) {
            $response->end(var_export($response->write(str_repeat('a', $size)), true));
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
