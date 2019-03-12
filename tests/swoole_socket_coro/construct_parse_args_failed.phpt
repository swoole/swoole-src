--TEST--
swoole_socket_coro: construct parse arguments failed
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
var_dump(new Co\Socket());
?>
--EXPECTF--
Fatal error: Uncaught ArgumentCountError: Swoole\Coroutine\Socket::__construct() expects at least 2 parameters, 0 given in %s/tests/swoole_socket_coro/construct_parse_args_failed.php:3
Stack trace:
#0 %s/tests/swoole_socket_coro/construct_parse_args_failed.php(3): Swoole\Coroutine\Socket->__construct()
#1 {main}
  thrown in %s/tests/swoole_socket_coro/construct_parse_args_failed.php on line 3
