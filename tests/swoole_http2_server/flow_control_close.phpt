--TEST--
swoole_http2_server: release a flow-control write after connection close
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

$pm = new ProcessManager;
$pm->setWaitTimeout(3);
$pm->parentFunc = function () use ($pm) {
    $client = http2_test_open_request($pm->getFreePort(), '/');
    $data = http2_test_wait_for_frame($client, 0);
    Assert::same($data['payload'], 'B');

    fclose($client);
    Assert::true($pm->wait());
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Request', function ($request, $response) use ($pm) {
        var_dump($response->write(str_repeat('B', 1024)));
        var_dump($response->end());
        $pm->wakeup();
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
bool(false)
bool(false)
