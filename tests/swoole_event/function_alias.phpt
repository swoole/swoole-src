--TEST--
swoole_event: function alias
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

var_dump(
    function_exists('swoole_event_add') &&
    function_exists('swoole_event_del') &&
    function_exists('swoole_event_set') &&
    function_exists('swoole_event_isset') &&
    function_exists('swoole_event_dispatch') &&
    function_exists('swoole_event_defer') &&
    function_exists('swoole_event_cycle') &&
    function_exists('swoole_event_write') &&
    function_exists('swoole_event_wait') &&
    function_exists('swoole_event_exit')
);

?>
--EXPECTF--
bool(true)
