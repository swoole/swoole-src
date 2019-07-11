--TEST--
swoole_coroutine/exception: double catch
--SKIPIF--
<?php require  __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

try {
    go(function () {
        try {
            echo "start\n";
            throw new Exception('coro Exception');
        } catch (Exception $e) {
            echo 'Caught exception: ',  $e->getMessage(), "\n";
        } finally {
            echo "finally in.\n";
        }
    });    
} catch (Exception $e) {
    echo 'Caught exception: ',  $e->getMessage(), "\n";
} finally {
    echo "finally out.\n";
}

echo "end\n";

?>
--EXPECT--
start
Caught exception: coro Exception
finally in.
finally out.
end
