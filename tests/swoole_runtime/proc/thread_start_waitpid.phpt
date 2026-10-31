--TEST--
swoole_runtime: wait for children while starting AIO and preemption threads
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\System;

Coroutine::set([
    'hook_flags' => SWOOLE_HOOK_ALL,
    'aio_core_worker_num' => 1,
    'aio_worker_num' => 2,
]);

foreach ([false, true] as $preemptive) {
    Coroutine::set(['enable_preemptive_scheduler' => $preemptive]);
    for ($i = 0; $i < 10; $i++) {
        Coroutine\run(function () {
            Assert::notEmpty(System::readFile(__FILE__));
            $process = proc_open([PHP_BINARY, '-n', '-r', 'exit(0);'], [
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ], $pipes);
            Assert::resource($process);
            fclose($pipes[1]);
            fclose($pipes[2]);
            Assert::same(proc_close($process), 0);
        });
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
