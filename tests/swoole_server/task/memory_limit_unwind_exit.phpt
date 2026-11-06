--TEST--
swoole_server/task: stop synchronous task loops after delayed OOM
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
foreach ([1, 2, 3] as $ipc) {
    $result = run_unwind_exit_php($code, ['task', 0, SWOOLE_PROCESS, $ipc]);
    assert_unwind_exit($result, 0, "OK\n");
    echo "ipc=$ipc: OK\n";
}
?>
--EXPECT--
ipc=1: OK
ipc=2: OK
ipc=3: OK
