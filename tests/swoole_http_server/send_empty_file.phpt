--TEST--
swoole_http_server: send empty file
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const TMP_FILE = '/tmp/sendfile.txt';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    Co\run(function () use ($pm) {
        file_put_contents(TMP_FILE, '');
        $recv_file = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}");
        unlink(TMP_FILE);
        Assert::same($recv_file, '');
    });
    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['worker_num' => 1]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->sendfile(TMP_FILE);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
