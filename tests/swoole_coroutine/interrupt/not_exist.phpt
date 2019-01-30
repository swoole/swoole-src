--TEST--
swoole_coroutine: throw coroutine which is not existing
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
go(function () {
    for ($n = MAX_LOOPS; $n--;) {
        $ret = Co::throw(mt_rand(2, PHP_INT_MAX));
        assert($ret === false && swoole_last_error() === SWOOLE_ERROR_CO_NOT_EXIST);
    }
    echo "DONE\n";
});
?>
--EXPECT--
DONE
