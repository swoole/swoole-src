--TEST--
swoole_http_server: sendfile invalid offset and length
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$file = '/tmp/swoole_sendfile_invalid_offset_length.txt';
file_put_contents($file, 'hello swoole');

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $body = file_get_contents("http://127.0.0.1:{$pm->getFreePort()}");
    Assert::same($body, 'DONE');
    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $file) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($file) {
        Assert::false(@$response->sendfile($file, -1));
        Assert::false(@$response->sendfile($file, 0, -1));
        $response->end('DONE');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
@unlink($file);
?>
--EXPECT--
DONE
