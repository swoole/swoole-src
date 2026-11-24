--TEST--
swoole_http2_server: GOAWAY debug data respects the negotiated frame size
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

$pm = new ProcessManager;
$pm->parentFunc = static function () use ($pm) {
    foreach ([16384, 32768] as $limit) {
        $client = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}", $errno, $error, 2);
        Assert::notSame($client, false);
        stream_set_timeout($client, 2);
        $request = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            . http2_test_frame(4, 0, 0, pack('nN', 5, $limit))
            . http2_test_request_headers(1, '/' . $limit);
        Assert::same(fwrite($client, $request), strlen($request));
        $frame = http2_test_wait_for_frame($client, 7);
        Assert::same($frame['flags'], 0);
        Assert::same($frame['streamId'], 0);
        Assert::same($frame['payload'], pack('NN', 1, SWOOLE_HTTP2_ERROR_ENHANCE_YOUR_CALM) . str_repeat('X', $limit - 8));
        fclose($client);
    }
    $pm->kill();
};
$pm->childFunc = static function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null', 'open_http2_protocol' => true]);
    $server->on('WorkerStart', static function () use ($pm) { $pm->wakeup(); });
    $server->on('Request', static function ($request, $response) {
        $limit = (int) substr($request->server['request_uri'], 1);
        Assert::false(@$response->goaway(0, str_repeat('X', $limit - 7)));
        Assert::false(@$response->goaway(0, str_repeat('X', 1 << 24)));
        Assert::true($response->goaway(SWOOLE_HTTP2_ERROR_ENHANCE_YOUR_CALM, str_repeat('X', $limit - 8)));
        $response->end();
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
