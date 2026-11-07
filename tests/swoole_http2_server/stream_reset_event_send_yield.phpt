--TEST--
swoole_http2_server: a reset response is not writable while its write waits for the connection
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

$pm = new ProcessManager;
$pm->setWaitTimeout(5);
$pm->parentFunc = function () use ($pm) {
    // The client never reads, so the write below fills the buffers and waits in send_yield.
    $client = http2_test_open_request($pm->getFreePort(), '/', 0x7fffffff);
    Assert::true($pm->wait());
    fwrite($client, http2_test_frame(3, 0, 1, pack('N', 8)));
    Assert::true($pm->wait());
    fclose($client);
    Assert::true($pm->wait());
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'http_compression' => false,
        'send_yield' => true,
        'buffer_output_size' => 1024 * 1024,
    ]);
    $writing = false;
    $writer = null;
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Request', function ($request, $response) use ($pm, &$writing, &$writer) {
        $writer = $response;
        $writing = true;
        $pm->wakeup();
        var_dump($response->write(str_repeat('A', 16 * 1024 * 1024)));
        $writing = false;
        $pm->wakeup();
    });
    $server->on('StreamReset', function ($server, $fd, $streamId) use ($pm, &$writing, &$writer) {
        Assert::true($writing);
        Assert::false($writer->isWritable());
        Assert::false($writer->write('x'));
        echo "reset while writing\n";
        $pm->wakeup();
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
reset while writing
bool(false)
