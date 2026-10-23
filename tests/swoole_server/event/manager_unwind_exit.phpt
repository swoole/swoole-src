--TEST--
swoole_server/event: stop manager startup and wait loops after delayed OOM
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
    foreach (['manager-start', 'manager-timer', 'manager-error'] as $target) {
        $result = run_unwind_exit_php($code, [$target, 0, $mode, 1]);
        assert_unwind_exit($result, 0, "OK\n");
        echo "mode=$mode $target: OK\n";
    }
}
?>
--EXPECT--
mode=1 manager-start: OK
mode=1 manager-timer: OK
mode=1 manager-error: OK
mode=2 manager-start: OK
mode=2 manager-timer: OK
mode=2 manager-error: OK
