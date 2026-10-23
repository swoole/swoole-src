--TEST--
swoole_process_pool: propagate UnwindExit from master and worker callbacks
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
skip_if_function_not_exist('proc_open');
skip_if_function_not_exist('posix_setsid');
skip_if_function_not_exist('posix_kill');
?>
--FILE--
<?php
require __DIR__ . '/../include/unwind_exit.inc';

foreach (['start', 'timer'] as $phase) {
    $result = run_unwind_exit_php(<<<'PHP'
swoole_async_set(['enable_coroutine' => false]);
$master = getmypid();
$phase = $argv[2];
register_shutdown_function(function () use ($master) {
    if (getmypid() === $master) {
        echo "master shutdown\n";
    }
});
$pool = new Swoole\Process\Pool(1);
$pool->on('Start', function () use ($phase) {
    if ($phase === 'start') {
        exit(29);
    }
    Swoole\Timer::after(20, fn() => exit(29));
});
$pool->on('WorkerStart', function () { sleep(5); });
$pool->on('Shutdown', fn() => print("unexpected shutdown callback\n"));
$pool->start();
echo "unexpected continuation\n";
PHP, [$phase]);
    assert_unwind_exit($result, 29, "master shutdown\n");
    echo "master $phase: OK\n";
}
$result = run_unwind_exit_php(<<<'PHP'
$directory = $argv[1];
swoole_async_set(['enable_coroutine' => false]);
$terminating = false;
register_shutdown_function(function () use (&$terminating) {
    if ($terminating) {
        echo "worker shutdown\n";
    }
});
$pool = new Swoole\Process\Pool(1);
$pool->on('Start', function ($pool) use ($directory) {
    Swoole\Timer::tick(20, function () use ($pool, $directory) {
        if (is_file($directory . '/respawn')) {
            $pool->shutdown();
        }
    });
});
$pool->on('WorkerStart', function () use ($directory, &$terminating) {
    if (is_file($directory . '/worker')) {
        file_put_contents($directory . '/respawn', (string) getmypid());
        sleep(5);
        return;
    }
    file_put_contents($directory . '/worker', (string) getmypid());
    $terminating = true;
    exit(31);
});
$pool->on('WorkerStop', function () use (&$terminating) {
    if ($terminating) {
        echo "unexpected worker stop\n";
    }
});
$pool->start();
if (file_get_contents($directory . '/worker') === file_get_contents($directory . '/respawn')) {
    throw new RuntimeException('The terminated worker was not replaced');
}
echo "worker respawned\nmaster returned\n";
PHP);
assert_unwind_exit($result, 0, "worker shutdown\nworker respawned\nmaster returned\n");
echo "worker: OK\n";
?>
--EXPECT--
master start: OK
master timer: OK
worker: OK
