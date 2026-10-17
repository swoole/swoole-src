--TEST--
swoole_http2_server: release a flow-control write after RST_STREAM
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
    Assert::same($data['payload'], 'A');

    fwrite($client, http2_test_frame(3, 0, 1, pack('N', 8)));
    Assert::true($pm->wait());

    $ping = '12345678';
    fwrite($client, http2_test_frame(6, 0, 0, $ping));
    $ack = http2_test_wait_for_frame($client, 6, 1);
    Assert::same($ack['payload'], $ping);
    fclose($client);
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
        var_dump($response->end(str_repeat('A', 1024)));
        $pm->wakeup();
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
bool(false)
