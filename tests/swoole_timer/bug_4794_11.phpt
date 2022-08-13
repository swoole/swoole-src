--TEST--
swoole_timer: #4794 Timer::add() (ERRNO 505): msec value[0] is invalid
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

ini_set('swoole.display_errors', 'off');

$cli = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
$r = $cli->connect("11.11.11.11", 80, 0.0005);
Assert::false($r);
Assert::eq($cli->errCode, SOCKET_ETIMEDOUT);
?>
--EXPECT--
