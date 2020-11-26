--TEST--
swoole_runtime/unsafe: pcntl_fork
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use function Swoole\Coroutine\run;

run(function ()  {
    pcntl_fork();
});
?>
--EXPECTF--
Warning: pcntl_fork() has been disabled for security reasons in %s on line %d
