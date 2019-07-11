--TEST--
swoole_http_client_coro: construct failed
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$http = new Co\Http\Client('');
?>
--EXPECTF--
Fatal error: Uncaught Swoole\Coroutine\Http\Client\Exception: host is empty in %s/tests/swoole_http_client_coro/construct_failed.php:3
Stack trace:
#0 %s/tests/swoole_http_client_coro/construct_failed.php(3): Swoole\Coroutine\Http\Client->__construct('')
#1 {main}
  thrown in %s/tests/swoole_http_client_coro/construct_failed.php on line 3
