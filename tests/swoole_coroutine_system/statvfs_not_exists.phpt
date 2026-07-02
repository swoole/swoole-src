--TEST--
swoole_coroutine_system: statvfs returns false when path does not exist
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;

run(function() {
    var_dump(System::statvfs(__DIR__ . '/not_exists_' . uniqid()));
});
?>
--EXPECT--
bool(false)
