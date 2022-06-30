--TEST--
swoole_timer: function alias
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

var_dump(
    function_exists('swoole_timer_set') &&
    function_exists('swoole_timer_after') &&
    function_exists('swoole_timer_tick') &&
    function_exists('swoole_timer_exists') &&
    function_exists('swoole_timer_info') &&
    function_exists('swoole_timer_stats') &&
    function_exists('swoole_timer_list') &&
    function_exists('swoole_timer_clear') &&
    function_exists('swoole_timer_clear_all')
);

?>
--EXPECTF--
bool(true)
