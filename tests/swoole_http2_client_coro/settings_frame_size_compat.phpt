--TEST--
swoole_http2_client_coro: retain legacy SETTINGS acceptance with bounded outgoing DATA frames
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

$settings = [0, 16383, 16777216];
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $settings) {
    try {
        Swoole\Coroutine\run(function () use ($pm, $settings) {
            foreach ($settings as $size) {
                $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
                Assert::true($client->connect());
                $request = new Swoole\Http2\Request;
                $request->headers = ['x-large' => str_repeat('0', 40000)];
                Assert::greaterThan($client->send($request), 0);
                Assert::isInstanceOf($client->recv(2), Swoole\Http2\Response::class);
                Assert::true($client->connected);
                $request = new Swoole\Http2\Request;
                $request->data = str_repeat('a', 40000);
                Assert::greaterThan($client->send($request), 0);
                Assert::isInstanceOf($client->recv(2), Swoole\Http2\Response::class);
                Assert::true($client->connected);
                $client->close();
            }
        });
    } finally {
        $pm->kill();
    }
};
$pm->childFunc = function () use ($pm, $settings) {
    $server = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort());
    $pm->wakeup();
    foreach ($settings as $size) {
        $connection = stream_socket_accept($server, 3);
        Assert::resource($connection);
        stream_set_timeout($connection, 2);
        Assert::same(fwrite($connection, http2_test_frame(4, 0, 0, pack('nN', 5, $size))), 15);
        Assert::same(http2_test_read_exact($connection, 24), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        $body = '';
        while (true) {
            $frame = http2_test_read_frame($connection);
            Assert::isArray($frame);
            if ($frame['type'] === 1 && $frame['streamId'] === 1) {
                Assert::greaterThan(strlen($frame['payload']), 16384);
                fwrite($connection, http2_test_frame(1, 5, 1, "\x88"));
            } elseif ($frame['type'] === 0 && $frame['streamId'] === 3) {
                Assert::lessThanEq(strlen($frame['payload']), $size < 16384 ? 16384 : 16777215);
                $body .= $frame['payload'];
                if ($frame['flags'] & 1) {
                    Assert::same($body, str_repeat('a', 40000));
                    fwrite($connection, http2_test_frame(1, 5, 3, "\x88"));
                    break;
                }
            }
        }
        fclose($connection);
    }
    fclose($server);
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
