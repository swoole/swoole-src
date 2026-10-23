--TEST--
swoole_process_pool: preserve delayed OOM termination in master and worker processes
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
skip_if_function_not_exist('proc_open');
skip_if_function_not_exist('posix_setsid');
skip_if_function_not_exist('posix_kill');
skip_if_in_valgrind('requires the Zend memory limit');
skip('requires delayed OOM support', ini_get('memory_hard_limit_percent') === false);
?>
--FILE--
<?php
require __DIR__ . '/../include/unwind_exit.inc';

foreach (['start', 'timer', 'worker'] as $phase) {
    $result = run_unwind_exit_php(<<<'PHP'
$directory = $argv[1];
swoole_async_set(['enable_coroutine' => false]);
$master = getmypid();
$phase = $argv[2];
$terminating = false;
function exhaust_memory(): void {
    $data = [];
    while (true) {
        $data[] = str_repeat('x', 1024 * 1024);
    }
}
register_shutdown_function(function () use ($master, &$terminating) {
    if ($terminating) {
        echo getmypid() === $master ? "master shutdown\n" : "worker shutdown\n";
    }
});
$pool = new Swoole\Process\Pool(1);
$pool->on('Start', function ($pool) use ($phase, $directory, &$terminating) {
    if ($phase === 'start') {
        $terminating = true;
        exhaust_memory();
    } elseif ($phase === 'timer') {
        Swoole\Timer::after(20, function () use (&$terminating) {
            $terminating = true;
            exhaust_memory();
        });
    } elseif ($phase === 'worker') {
        Swoole\Timer::tick(20, function () use ($pool, $directory) {
            if (is_file($directory . '/respawn')) {
                $pool->shutdown();
            }
        });
    }
});
$pool->on('WorkerStart', function () use ($phase, $directory, &$terminating) {
    if ($phase === 'worker') {
        if (is_file($directory . '/worker')) {
            file_put_contents($directory . '/respawn', (string) getmypid());
            sleep(5);
            return;
        }
        file_put_contents($directory . '/worker', (string) getmypid());
        $terminating = true;
        exhaust_memory();
    }
    sleep(5);
});
$pool->on('WorkerStop', function () use (&$terminating) {
    if ($terminating) {
        echo "unexpected worker stop\n";
    }
});
$pool->on('Shutdown', function () use (&$terminating) {
    if ($terminating) {
        echo "unexpected shutdown callback\n";
    }
});
$pool->start();
if ($phase === 'worker') {
    if (file_get_contents($directory . '/worker') === file_get_contents($directory . '/respawn')) {
        throw new RuntimeException('The terminated worker was not replaced');
    }
    echo "worker respawned\n";
}
echo "master returned\n";
PHP, [$phase]);
    if ($phase === 'worker') {
        assert_unwind_exit($result, 0, "worker shutdown\nworker respawned\nmaster returned\n");
    } else {
        assert_unwind_exit($result, 255, "master shutdown\n");
    }
    echo "$phase: OK\n";
}
?>
--EXPECT--
start: OK
timer: OK
worker: OK
