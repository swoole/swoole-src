--TEST--
swoole_coroutine/exception: exception after yield
--SKIPIF--
<?php require  __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine as co;
go(function () {
    try {
        echo "start\n";
        co::sleep(.001);
        echo "after sleep\n";
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
end
after sleep
Caught exception: coro Exception
finally.
