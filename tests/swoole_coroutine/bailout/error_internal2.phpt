--TEST--
swoole_coroutine/bailout: error
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
ini_set('memory_limit', '1M');
go(function(){
    $n = 1000;
    while ($n--) {
        go(function () {
            $a = str_repeat('A', 1024);
            co::sleep(0.1);
        });
    }
});
?>
--EXPECTF--
Fatal error: Allowed memory size of %d bytes exhausted %s
