--TEST--
swoole_http2_server: a reset is reported for a request waiting on worker_max_concurrency
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine\Channel;

$pm = new ProcessManager;
$pm->setWaitTimeout(3);
$pm->parentFunc = function () use ($pm) {
    $client = http2_test_open_request($pm->getFreePort(), '/', 65535);
    Assert::true($pm->wait());
    // Stream 3 waits for stream 1's slot when it is reset.
    fwrite($client, http2_test_request_headers(3, '/'));
    fwrite($client, http2_test_frame(3, 0, 3, pack('N', 8)));
    $data = http2_test_wait_for_frame($client, 0);
    Assert::same([$data['streamId'], $data['payload']], [1, 'one']);
    // Stream 3 released the slot too.
    fwrite($client, http2_test_request_headers(5, '/'));
    $data = http2_test_wait_for_frame($client, 0);
    Assert::same([$data['streamId'], $data['payload']], [5, 'five']);
    fclose($client);
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'worker_max_concurrency' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
    ]);
    $handlers = [];
    $release = new Channel(1);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Request', function ($request, $response) use ($pm, &$handlers, $release) {
        $handlers[$request->streamId] = true;
        if ($request->streamId === 1) {
            $pm->wakeup();
            $release->pop();
            $response->end('one');
        } elseif ($request->streamId === 3) {
            echo 'stream 3 handler, writable: ', var_export($response->isWritable(), true), "\n";
        } else {
            $response->end('five');
        }
    });
    $server->on('StreamReset', function ($server, $fd, $streamId) use (&$handlers, $release) {
        echo "reset stream {$streamId}, handler started: ", var_export(isset($handlers[$streamId]), true), "\n";
        $release->push(true);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
reset stream 3, handler started: false
stream 3 handler, writable: false
