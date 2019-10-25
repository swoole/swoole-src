--TEST--
swoole_coroutine_system: sleep
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Coroutine::create(function () {
    Swoole\Coroutine\System::sleep(0.5);
    echo "OK";
});

?>
--EXPECT--
OK
