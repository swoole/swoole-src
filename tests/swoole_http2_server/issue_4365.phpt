--TEST--
swoole_http2_server: github issue#4365
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;

const N = 265537;

$pm->parentFunc = function ($pid) use ($pm) {
    if (Assert::assert(!empty($res = `curl -s --http2-prior-knowledge http://127.0.0.1:{$pm->getFreePort()}/ > /dev/stdout 2>/dev/null`))) {
        Assert::length($res, N);
        echo "DONE\n";
    }
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $http->set([
        'open_http2_protocol' => true,
        'enable_reuse_port' => true,
        'enable_coroutine' => false,
        'log_level' => 1,
        'log_file' => TEST_LOG_FILE,
    ]);
    $http->on('request', function ($request, $response) {
        $response->end(str_repeat('x', N));
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
