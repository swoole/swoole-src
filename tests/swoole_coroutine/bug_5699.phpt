--TEST--
swoole_coroutine: Github bug #5699
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
ini_set('swoole.enable_fiber_mock', 'On');
use function Swoole\Coroutine\run;

run(function() {
    sleep(1);
});
?>
--EXPECT--
