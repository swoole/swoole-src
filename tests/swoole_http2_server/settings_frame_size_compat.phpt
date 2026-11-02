--TEST--
swoole_http2_server: retain legacy SETTINGS acceptance with bounded outgoing DATA frames
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    try {
        foreach ([0, 16383, 16777216] as $size) {
            $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort(), $errno, $errstr, 2);
            Assert::resource($client);
            stream_set_timeout($client, 2);
            try {
                $request = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                    . http2_test_frame(4, 0, 0, pack('nN', 5, $size))
                    . http2_test_request_headers(1, '/');
                Assert::same(fwrite($client, $request), strlen($request));
                $body = '';
                while (true) {
                    $frame = http2_test_wait_for_frame($client, 0);
                    Assert::lessThanEq(strlen($frame['payload']), $size < 16384 ? 16384 : 16777215);
                    $body .= $frame['payload'];
                    if ($frame['flags'] & 1) {
                        break;
                    }
                }
                Assert::same($body, str_repeat('a', 40000));
                fwrite($client, http2_test_frame(6, 0, 0, 'still-ok'));
                Assert::same(http2_test_wait_for_frame($client, 6, 1)['payload'], 'still-ok');
            } finally {
                fclose($client);
            }
        }
    } finally {
        $pm->kill();
    }
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'open_http2_protocol' => true,
        'http_compression' => false,
        'log_file' => '/dev/null',
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Request', function ($request, $response) {
        Assert::true($response->end(str_repeat('a', 40000)));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
