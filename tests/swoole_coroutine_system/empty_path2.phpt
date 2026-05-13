--TEST--
swoole_coroutine_system: writeFile check
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;

run(function() {
    System::statvfs('');
});
?>
--EXPECTF--
Fatal error: Uncaught ValueError: Path cannot be empty in %s:%d
Stack trace:
#0 %s(%d): Swoole\Coroutine\System::statvfs('')
#1 [internal function]: {closure%s}()
#2 {main}
  thrown in %s on line %d
