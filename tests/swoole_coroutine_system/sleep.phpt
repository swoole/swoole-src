--TEST--
swoole_coroutine_system: sleep
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;

co::create(function () {
    co::sleep(0.5);
    echo "OK";
});

?>
--EXPECT--
OK