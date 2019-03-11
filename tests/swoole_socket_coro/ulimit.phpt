--TEST--
swoole_socket_coro: new socket failed
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
if ($argv[1] ?? '' === 'ulimit') {
    for ($n = MAX_CONCURRENCY_LOW + 1; $n--;) {
        $sockets[] = new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    }
} else {
    $n = MAX_CONCURRENCY_LOW;
    $_SERVER['TEST_PHP_EXECUTABLE'] = $_SERVER['TEST_PHP_EXECUTABLE'] ?? 'php';
    `ulimit -n {$n} && {$_SERVER['TEST_PHP_EXECUTABLE']} {$_SERVER['PHP_SELF']} ulimit`;
}
?>
--EXPECTF--
PHP Fatal error:  Uncaught Swoole\Coroutine\Socket\Exception: new Socket() failed. Error: Too many open files [%d] in %s/tests/swoole_socket_coro/ulimit.php:%d
Stack trace:
#0 %s/tests/swoole_socket_coro/ulimit.php(%d): Swoole\Coroutine\Socket->__construct(%d, %d, %d)
#1 {main}
  thrown in %s/tests/swoole_socket_coro/ulimit.php on line %d
