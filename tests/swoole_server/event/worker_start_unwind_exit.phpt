--TEST--
swoole_server/event: do not restart native loops after WorkerStart terminates
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_win();
skip_if_function_not_exist('proc_open');
skip_if_function_not_exist('posix_setsid');
skip_if_function_not_exist('pcntl_fork');
skip_if_function_not_exist('posix_kill');
skip_if_in_valgrind('requires the Zend memory limit');
skip('requires delayed OOM support', ini_get('memory_hard_limit_percent') === false);
?>
--FILE--
<?php
require __DIR__ . '/../../include/unwind_exit.inc';
$code = 'require ' . var_export(__DIR__ . '/../../include/api/unwind_exit_server.php', true) . ';';
foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    foreach ([0, 1] as $coroutines) {
        $result = run_unwind_exit_php($code, ['event-start', $coroutines, $mode, 1]);
        assert_unwind_exit($result, 0, "OK\n");
        echo "mode=$mode coroutine=$coroutines: OK\n";
    }
}
$result = run_unwind_exit_php($code, ['task-start', 0, SWOOLE_PROCESS, 1]);
assert_unwind_exit($result, 0, "OK\n");
echo "task worker: OK\n";
?>
--EXPECT--
mode=1 coroutine=0: OK
mode=1 coroutine=1: OK
mode=2 coroutine=0: OK
mode=2 coroutine=1: OK
task worker: OK
