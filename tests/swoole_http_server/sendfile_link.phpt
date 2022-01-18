--TEST--
swoole_http_server: sendfile link
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const FILE = '/tmp/sendfile.txt';
const LINK = '/tmp/sendfile.txt.link';

$send_file = get_safe_random(mt_rand(0, 65535 * 10));
file_put_contents(FILE, $send_file);
link(FILE, LINK);

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm, $send_file) {
    $recv_file = @file_get_contents("http://127.0.0.1:{$pm->getFreePort()}");
    Assert::eq($recv_file, $send_file);
    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function ($request, $response) {
        $response->header('Content-Type', 'application/octet-stream', true);
        Assert::eq($response->sendfile(LINK), true);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
unlink(LINK);
unlink(FILE);
?>
--EXPECT--
DONE
