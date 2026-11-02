--TEST--
swoole_http2_server: apply peer frame size changes after a flow-control wait
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function http2_frame(int $type, int $flags, int $streamId, string $payload = ''): string
{
    return substr(pack('N', strlen($payload)), 1)
        . chr($type)
        . chr($flags)
        . pack('N', $streamId)
        . $payload;
}

function read_exact($client, int $length): string
{
    $data = '';
    while (strlen($data) < $length) {
        $chunk = fread($client, $length - strlen($data));
        if ($chunk === false || $chunk === '') {
            throw new RuntimeException('Failed to read HTTP/2 frame');
        }
        $data .= $chunk;
    }
    return $data;
}

function read_frame($client): array
{
    $header = read_exact($client, 9);
    $length = unpack('N', "\0" . substr($header, 0, 3))[1];
    return [
        'type' => ord($header[3]),
        'flags' => ord($header[4]),
        'streamId' => unpack('N', substr($header, 5, 4))[1] & 0x7fffffff,
        'payload' => read_exact($client, $length),
    ];
}

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm) {
        $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort(), $errno, $errstr, 2);
        Assert::resource($client);
        stream_set_timeout($client, 2);

        try {
            $request = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                . http2_frame(4, 0, 0, pack('nN', 5, 65536))
                . http2_frame(1, 5, 1, "\x82\x86\x84\x01\x09localhost");
            Assert::same(fwrite($client, $request), strlen($request));

            $body = '';
            $changed = false;
            $ackCount = 0;
            $frameLengths = [];
            while (true) {
                $frame = read_frame($client);
                if ($frame['type'] === 4) {
                    if ($frame['flags'] & 1) {
                        ++$ackCount;
                    } else {
                        fwrite($client, http2_frame(4, 1, 0));
                    }
                }
                if ($frame['type'] !== 0 || $frame['streamId'] !== 1) {
                    continue;
                }

                $body .= $frame['payload'];
                if ($ackCount === 2) {
                    $frameLengths[] = strlen($frame['payload']);
                }

                // Exhaust the initial window before changing the limit and resuming the sender.
                if (strlen($body) === 65535 && !$changed) {
                    $changed = true;
                    $update = http2_frame(4, 0, 0, pack('nN', 5, 16384))
                        . http2_frame(8, 0, 0, pack('N', 200000))
                        . http2_frame(8, 0, 1, pack('N', 200000));
                    Assert::same(fwrite($client, $update), strlen($update));
                }
                if ($frame['flags'] & 1) {
                    break;
                }
            }
        } finally {
            fclose($client);
            $pm->kill();
        }

        Assert::true($changed);
        Assert::same($ackCount, 2);
        Assert::same($body, str_repeat('a', 200000));
        Assert::greaterThan(count($frameLengths), 0);
        Assert::lessThanEq(max($frameLengths), 16384);
    };
    $pm->childFunc = function () use ($pm, $mode) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'worker_num' => 1,
            'reactor_num' => 1,
            'open_http2_protocol' => true,
            'http_compression' => false,
            'log_file' => '/dev/null',
        ]);
        $server->on('WorkerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $server->on('Request', function ($request, $response) {
            Assert::true($response->end(str_repeat('a', 200000)));
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
