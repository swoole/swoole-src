--TEST--
swoole_http_server: http server callback use new object method
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    curlGet("http://127.0.0.1:{$pm->getFreePort()}");
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('0.0.0.0', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);
    $http->on('request', 'var_dump');
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
