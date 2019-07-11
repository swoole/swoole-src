--TEST--
swoole_coroutine/exception: IO empty Exception
--SKIPIF--
<?php require  __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

go(function () {
    try {
        echo "start\n";
        throw new Exception('coro Exception');
    } catch (Exception $e) {
        echo 'Caught exception: ',  $e->getMessage(), "\n";
    } finally {
        echo "finally.\n";
    }
});
echo "end\n";

?>
--EXPECT--
start
Caught exception: coro Exception
finally.
end
