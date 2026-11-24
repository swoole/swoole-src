--TEST--
swoole_server: stats_file [php]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\run;

const STATS_FILE = __DIR__ . '/stats_file_php_stats.php';
Assert::setThrowException(true);

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    @unlink(STATS_FILE);
    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm) {
        try {
            run(function () use ($pm) {
                Assert::same(httpGetBody('http://127.0.0.1:' . $pm->getFreePort()), 'OK');
                $stats = include STATS_FILE;
                Assert::isArray($stats);
                assert_server_stats($stats);
            });
        } finally {
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'stats_file' => STATS_FILE,
            'stats_timer_interval' => 20,
            'log_file' => DEV_NULL,
            'worker_num' => 1,
        ]);
        $server->on($mode === SWOOLE_PROCESS ? 'Start' : 'WorkerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $server->on('request', function ($request, $response) use ($server) {
            $deadline = microtime(true) + 5;
            while (!is_file(STATS_FILE) && microtime(true) < $deadline) {
                Co::sleep(0.001);
                clearstatcache(true, STATS_FILE);
            }
            Assert::true(is_file(STATS_FILE));
            // Stop rewriting before the parent includes the file, and leave no timer to delay shutdown.
            Assert::true(Swoole\Timer::clear($server->stats_timer));
            $response->end('OK');
        });
        $server->start();
    };
    $pm->childFirst();
    try {
        $pm->run();
    } finally {
        @unlink(STATS_FILE);
    }
}
?>
--EXPECT--
