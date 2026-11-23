--TEST--
swoole_http2_server: window waits have a deadline, send GOAWAY and release all blocked responses
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_flow_control.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS, 'coroutine'] as $mode) {
    foreach ([false, true] as $tls) {
        foreach ([false, true] as $drip) {
            $pm = new ProcessManager();
            $pm->parentFunc = function () use ($pm, $tls, $drip) {
                try {
                    $peer = new Http2FlowPeer($pm->getFreePort(), 0, $tls);
                    $peer->request(1, '/wait');
                    $peer->request(3, '/wait');
                    $started = microtime(true);
                    $peer->barrier();
                    $goaway = null;
                    if ($drip) {
                        // Keep granting single bytes: progress must not restart the operation's deadline.
                        while (true) {
                            $data = http2_test_frame(8, 0, 0, pack('N', 1))
                                . http2_test_frame(8, 0, 1, pack('N', 1))
                                . http2_test_frame(6, 0, 0, 'deadline');
                            if (@fwrite($peer->socket, $data) !== strlen($data)) {
                                break;
                            }
                            $frame = @http2_test_read_frame($peer->socket);
                            if ($frame === false) {
                                break;
                            }
                            if ($frame['type'] === 0) {
                                $peer->total += strlen($frame['payload']);
                            }
                            if ($frame['type'] === 7) {
                                $goaway = $frame;
                                break;
                            }
                        }
                        Assert::greaterThan($peer->total, 0);
                    } else {
                        // Control traffic does not consume DATA credit.
                        for ($i = 0; $i < 10; ++$i) {
                            $peer->send(6, 0, 0, pack('J', $i));
                        }
                        do {
                            $goaway = $peer->read();
                        } while ($goaway['type'] !== 7);
                        Assert::same($peer->total, 0);
                    }
                    Assert::lessThan(microtime(true) - $started, 2.0);
                    if ($goaway !== null) {
                        Assert::same(unpack('N', substr($goaway['payload'], 4, 4))[1], 0);
                        Assert::contains(substr($goaway['payload'], 8), 'timeout');
                    }
                    $peer->closed();
                    $peer->close();

                    $peer = new Http2FlowPeer($pm->getFreePort(), 65535, $tls);
                    $peer->request(1, '/alive');
                    $peer->bytes(1, 1);
                    Assert::same($peer->bodies[1], '2');
                    $peer->close();
                } finally {
                    $pm->kill();
                }
            };
            $pm->childFunc = function () use ($pm, $mode, $tls) {
                $finished = new Swoole\Coroutine\Channel(2);
                http2_flow_server($pm, $mode, function ($request, $response) use ($finished) {
                    if ($request->server['request_uri'] === '/alive') {
                        Assert::false($finished->pop(1));
                        Assert::false($finished->pop(1));
                        $response->end('2');
                    } else {
                        $finished->push($response->end(str_repeat('A', 1024 * 1024)));
                    }
                }, $tls, [$mode === 'coroutine' ? 'write_timeout' : 'send_timeout' => 0.15]);
            };
            $pm->childFirst();
            $pm->run();
        }
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
