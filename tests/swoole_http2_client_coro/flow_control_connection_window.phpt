--TEST--
swoole_http2_client_coro: keep the connection window open with a custom http2_init_window_size
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

// Not a multiple of the frame size, so a response can end partway through a window
const BODY_SIZE = 200000;
const WINDOW_SIZES = [16384, 1024 * 1024];

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    try {
        Swoole\Coroutine\run(function () use ($pm) {
            foreach (WINDOW_SIZES as $windowSize) {
                Swoole\Coroutine::set(['http2_init_window_size' => $windowSize]);
                $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
                // The second connection reuses the client
                for ($i = 0; $i < 2; $i++) {
                    Assert::true($client->connect());
                    for ($j = 0; $j < 2; $j++) {
                        Assert::greaterThan($client->send(new Swoole\Http2\Request), 0);
                        $response = $client->recv(3);
                        Assert::isInstanceOf($response, Swoole\Http2\Response::class);
                        Assert::same(strlen($response->data), BODY_SIZE);
                    }
                    $client->close();
                }
            }
        });
    } finally {
        $pm->kill();
    }
};
$pm->childFunc = function () use ($pm) {
    $server = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort());
    $pm->wakeup();
    for ($n = count(WINDOW_SIZES) * 2; $n--;) {
        $connection = stream_socket_accept($server, 3);
        Assert::resource($connection);
        stream_set_timeout($connection, 2);
        fwrite($connection, http2_test_frame(4, 0, 0));
        Assert::same(http2_test_read_exact($connection, 24), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        // Send no more than the client's stream and connection windows allow
        $initialWindow = 65535;
        $connectionWindow = 65535;
        $streamId = 0;
        $streamWindow = 0;
        $read = function () use ($connection, &$initialWindow, &$connectionWindow, &$streamId, &$streamWindow) {
            $frame = http2_test_read_frame($connection);
            if ($frame === false) {
                throw new RuntimeException('failed to read HTTP/2 frame');
            }
            if ($frame['type'] === 4 && ($frame['flags'] & 1) === 0) {
                foreach (str_split($frame['payload'], 6) as $setting) {
                    $setting = unpack('nid/Nvalue', $setting);
                    if ($setting['id'] === 4) {
                        $initialWindow = $setting['value'];
                    }
                }
                fwrite($connection, http2_test_frame(4, 1, 0));
            } elseif ($frame['type'] === 8) {
                $increment = unpack('N', $frame['payload'])[1];
                if ($frame['streamId'] === 0) {
                    $connectionWindow += $increment;
                } elseif ($frame['streamId'] === $streamId) {
                    $streamWindow += $increment;
                }
            } elseif ($frame['type'] === 1) {
                $streamId = $frame['streamId'];
                $streamWindow = $initialWindow;
            }
            return $frame;
        };

        for ($i = 0; $i < 2; $i++) {
            while ($read()['type'] !== 1);
            fwrite($connection, http2_test_frame(1, 4, $streamId, "\x88"));
            for ($sent = 0; $sent < BODY_SIZE; $sent += $length) {
                while (($length = min(16384, BODY_SIZE - $sent, $connectionWindow, $streamWindow)) <= 0) {
                    $read();
                }
                $connectionWindow -= $length;
                $streamWindow -= $length;
                $end = $sent + $length === BODY_SIZE ? 1 : 0;
                fwrite($connection, http2_test_frame(0, $end, $streamId, str_repeat('a', $length)));
            }
        }
        // Read until the client closes, so unread frames don't turn our close into a reset
        while (http2_test_read_frame($connection) !== false);
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
