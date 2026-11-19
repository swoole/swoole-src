--TEST--
swoole_http2_server: an uncaught peer reset cancellation is fatal
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine\Channel;

$pm = new ProcessManager;
$pm->setWaitTimeout(5);
$pm->parentFunc = function () use ($pm) {
    $client = http2_test_open_request($pm->getFreePort(), '/');
    try {
        $pm->wait();
        fwrite($client, http2_test_frame(3, 0, 1, pack('N', 8)));
        while (($data = fread($client, 8192)) !== false && $data !== '') {
            // Consume the frames already sent before the request was canceled.
        }
        Assert::true(feof($client));
    } finally {
        fclose($client);
        $pm->kill();
    }
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'open_http2_protocol' => true,
        'http2_cancel_on_stream_reset' => true,
        'log_file' => '/dev/null',
    ]);
    $release = new Channel(1);
    $server->on('WorkerStart', fn () => $pm->wakeup());
    $server->on('Request', function () use ($pm, $release) {
        $pm->wakeup();
        try {
            $release->pop(5);
            echo "request continued\n";
        } finally {
            echo "request cleanup\n";
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
request cleanup

Fatal error: Uncaught Swoole\Coroutine\CanceledException in %s:%d
Stack trace:
%A
  thrown in %s on line %d
