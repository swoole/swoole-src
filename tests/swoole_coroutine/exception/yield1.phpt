--TEST--
swoole_coroutine/exception: exception before yield
--SKIPIF--
<?php require  __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine as co;
go(function () {
    try {
        echo "start\n";
        throw new Exception('coro Exception');
        co::sleep(.001);
        echo "after sleep\n";
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
