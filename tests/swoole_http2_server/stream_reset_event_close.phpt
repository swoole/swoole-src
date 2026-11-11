--TEST--
swoole_http2_server: the streamReset callback can close the connection
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
        fwrite($client, http2_test_frame(3, 0, 3, pack('N', 8)));
        Assert::true($pm->wait());
        while (http2_test_read_frame($client) !== false);
        Assert::true(feof($client));
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
        $responses = [];
        $sibling = new Channel(1);
        $server->on('WorkerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $server->on('Request', function ($request, $response) use ($pm, &$responses, $sibling) {
            $responses[$request->streamId] = $response;
            if (count($responses) === 2) {
                $pm->wakeup();
            }
            if ($request->streamId === 1) {
                Assert::true($sibling->pop(2));
                echo 'sibling writable: ', var_export($response->isWritable(), true), "\n";
                Assert::false($response->end('late'));
                $pm->wakeup();
            }
        });
        $server->on('StreamReset', function ($server, $fd, $streamId) {
            echo "reset stream {$streamId}\n";
            Assert::true($server->close($fd));
        });
        $server->on('Close', function () use ($sibling) {
            echo "close\n";
            // The HTTP/2 session is released after this callback returns.
            Swoole\Event::defer(fn () => $sibling->push(true));
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
?>
--EXPECT--
reset stream 3
close
sibling writable: false
reset stream 3
close
sibling writable: false
