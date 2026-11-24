--TEST--
swoole_thread: close coroutine process pipes independently in each thread
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
skip_if_nts();
skip_if_function_not_exist('proc_open');
?>
--FILE--
<?php
use Swoole\Coroutine;
use Swoole\Runtime;
use Swoole\Thread;

$worker = null;
if (!Thread::getArguments()) {
    Runtime::enableCoroutine(SWOOLE_HOOK_PROC);
    $worker = new Thread(__FILE__, true);
}
$role = $worker ? 'main' : 'worker';
Coroutine\run(static function () use ($role): void {
    for ($i = 0; $i < 8; $i++) {
        $expected = $role . '-' . $i;
        $process = proc_open([PHP_BINARY, '-n', '-r', 'echo $argv[1];', $expected], [1 => ['pipe', 'w']], $pipes);
        if (!is_resource($process)) {
            throw new RuntimeException('Unable to start child process');
        }

        $output = stream_get_contents($pipes[1]);
        $closed = fclose($pipes[1]);
        $exit = proc_close($process);
        if ($output !== $expected || !$closed || $exit !== 0) {
            throw new RuntimeException('Unexpected process pipe result');
        }
    }
});

if ($worker) {
    $worker->join();
    if ($worker->getExitStatus() !== 0) {
        throw new RuntimeException('Worker failed');
    }
    echo "DONE\n";
}
?>
--EXPECT--
DONE
