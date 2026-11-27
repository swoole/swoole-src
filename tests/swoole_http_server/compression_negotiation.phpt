--TEST--
swoole_http_server: negotiate compression weights and preserve Vary fields
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_constant_not_defined('SWOOLE_HAVE_ZLIB');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/http_compression_negotiation.inc';

SwooleTest\Assert::setThrowException(true);
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    try {
        Co\run(fn () => compression_negotiation_test($pm->getFreePort()));
    } finally {
        $pm->kill();
    }
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'http_compression_min_length' => 128,
        'http_compression_types' => ['text/html'],
    ]);
    $server->on('workerStart', fn () => $pm->wakeup());
    $server->on('request', 'compression_negotiation_response');
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
