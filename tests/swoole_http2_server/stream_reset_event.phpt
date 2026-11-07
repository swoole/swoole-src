--TEST--
swoole_http2_server: notify a stream reset after its request has been received
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine\Channel;

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm = new ProcessManager;
    $pm->setWaitTimeout(3);
    $pm->parentFunc = function () use ($pm) {
        $client = http2_test_open_request($pm->getFreePort(), '/', 65535);
        fwrite($client, http2_test_request_headers(3, '/'));
        Assert::true($pm->wait());

        fwrite($client, http2_test_frame(3, 0, 1, pack('N', 8)));
        $data = http2_test_wait_for_frame($client, 0);
        Assert::same($data['streamId'], 3);
        Assert::same($data['payload'], 'K');

        // Neither a finished stream nor one whose request is incomplete is reported.
        fwrite($client, http2_test_frame(3, 0, 3, pack('N', 8)));
        fwrite($client, http2_test_frame(1, 4, 5, substr(http2_test_request_headers(5, '/'), 9)));
        fwrite($client, http2_test_frame(3, 0, 5, pack('N', 8)));
        fwrite($client, http2_test_frame(6, 0, 0, '12345678'));
        $ack = http2_test_wait_for_frame($client, 6, 1);
        Assert::same($ack['payload'], '12345678');
        fclose($client);
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $mode) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'worker_num' => 1,
            'log_file' => '/dev/null',
            'open_http2_protocol' => true,
        ]);
        $requests = [];
        $server->on('WorkerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $server->on('Request', function ($request, $response) use ($pm, &$requests) {
            $channel = new Channel(1);
            $requests[$request->streamId] = [$request->fd, $response, $channel];
            if (count($requests) === 2) {
                $pm->wakeup();
            }
            if ($request->streamId === 1) {
                Assert::true($channel->pop(2));
                echo "stream 1 stopped\n";
                $requests[3][2]->push(true);
            } else {
                Assert::true($channel->pop(2));
                Assert::true($response->end('K'));
            }
        });
        $server->on('StreamReset', function ($server, $fd, $streamId) use (&$requests) {
            echo "reset stream {$streamId}\n";
            [$requestFd, $response, $channel] = $requests[$streamId];
            Assert::same($fd, $requestFd);
            Assert::false($response->isWritable());
            Assert::false($response->write('x'));
            $channel->push(true);
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
?>
--EXPECT--
reset stream 1
stream 1 stopped
reset stream 1
stream 1 stopped
