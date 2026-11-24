--TEST--
swoole_http2_server: exceeding the body limit resets only the request stream
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

$pm = new ProcessManager;
$pm->parentFunc = static function () use ($pm) {
    $client = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}", $errno, $error, 2);
    Assert::notSame($client, false);
    stream_set_timeout($client, 2);
    $request = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" . http2_test_frame(4, 0, 0)
        . http2_test_frame(1, 4, 1, "\x83\x86\x84\x01\x09localhost")
        . str_repeat(http2_test_frame(0, 0, 1, str_repeat('A', 16384)), 4)
        . http2_test_frame(0, 1, 1, 'C');
    Assert::same(fwrite($client, $request), strlen($request));
    $reset = http2_test_wait_for_frame($client, 3);
    Assert::same($reset['streamId'], 1);
    Assert::same($reset['flags'], 0);
    Assert::same($reset['payload'], pack('N', SWOOLE_HTTP2_ERROR_NO_ERROR));

    // A bad RST_STREAM payload length would desynchronise this next frame.
    fwrite($client, http2_test_frame(6, 0, 0, '12345678'));
    Assert::same(http2_test_wait_for_frame($client, 6, 1)['payload'], '12345678');
    fwrite($client, http2_test_request_headers(3, '/'));
    $response = http2_test_wait_for_frame($client, 0);
    Assert::same($response['streamId'], 3);
    Assert::same($response['payload'], 'ok');
    fclose($client);
    $pm->kill();
};
$pm->childFunc = static function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null', 'open_http2_protocol' => true, 'package_max_length' => 65536]);
    $server->on('WorkerStart', static function () use ($pm) { $pm->wakeup(); });
    $server->on('Request', static function ($request, $response) { $response->end('ok'); });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
