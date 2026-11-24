--TEST--
swoole_http2_server: max_concurrent_streams limit enforcement
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_request_trailer.php';

const MAX_STREAMS = 4;
Assert::setThrowException(true);

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $socket = http2_trailer_connect($pm->getFreePort());
    try {
        $accepted = $refused = [];
        for ($i = 0; $i < MAX_STREAMS * 2; $i++) {
            $id = $i * 2 + 1;
            if ($i < MAX_STREAMS) {
                $accepted[] = $id;
            } else {
                $refused[] = $id;
            }
            http2_trailer_send($socket, 1, 5, $id, http2_trailer_headers('/', 'GET'));
        }

        // The coroutine client discards RST_STREAM. Inspect the frames to verify every refusal directly.
        $resets = [];
        while (count($resets) < MAX_STREAMS) {
            $frame = http2_test_read_frame($socket);
            Assert::notSame($frame, false);
            if ($frame['type'] === 4 && ($frame['flags'] & 1) === 0) {
                http2_trailer_send($socket, 4, 1, 0);
            } elseif ($frame['type'] === 3) {
                Assert::same(unpack('N', $frame['payload'])[1], SWOOLE_HTTP2_ERROR_REFUSED_STREAM);
                Assert::false(isset($resets[$frame['streamId']]));
                $resets[$frame['streamId']] = true;
            } else {
                Assert::notSame($frame['type'], 7);
                Assert::notSame($frame['type'], 0);
            }
        }
        Assert::same(array_keys($resets), $refused);

        // A separate connection releases the held handlers only after all refusals have arrived.
        Assert::same(file_get_contents('http://127.0.0.1:' . $pm->getFreePort() . '/release'), 'released');
        $bodies = $completed = [];
        while (count($completed) < MAX_STREAMS) {
            $frame = http2_test_read_frame($socket);
            Assert::notSame($frame, false);
            Assert::notSame($frame['type'], 7);
            Assert::notSame($frame['type'], 3);
            $id = $frame['streamId'];
            if ($frame['type'] === 0) {
                $bodies[$id] = ($bodies[$id] ?? '') . $frame['payload'];
            }
            if (($frame['type'] === 0 || $frame['type'] === 1) && ($frame['flags'] & 1)) {
                Assert::same($bodies[$id] ?? '', 'OK');
                Assert::false(isset($completed[$id]));
                $completed[$id] = true;
            }
        }
        $ids = array_keys($completed);
        sort($ids);
        Assert::same($ids, $accepted);
    } finally {
        fclose($socket);
        $pm->kill();
    }
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $release = new Swoole\Coroutine\Channel(1);
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'http2_max_concurrent_streams' => MAX_STREAMS,
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function ($request, $response) use ($release) {
        if ($request->server['request_uri'] === '/release') {
            $release->close();
            $response->end('released');
            return;
        }
        $release->pop();
        $response->end('OK');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
