--TEST--
swoole_http_server: sendfile
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$send_file_path = __DIR__ . '/sendfile.tmp';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm, $send_file_path) {
    for ($i = MAX_REQUESTS; $i--;) {
        $send_file = get_safe_random(mt_rand(0, 65535 * 10));
        file_put_contents($send_file_path, $send_file);
        $recv_file = file_get_contents("http://127.0.0.1:{$pm->getFreePort()}");
        Assert::same($send_file, $recv_file);
    }
    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $send_file_path) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($send_file_path) {
        $response->header('Content-Type', 'application/octet-stream');
        $response->header('Content-Disposition', 'attachment; filename=recvfile.txt');
        $response->sendfile($send_file_path);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
unlink($send_file_path);
?>
--EXPECT--
DONE
