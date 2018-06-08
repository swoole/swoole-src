--TEST--
swoole_coroutine: exception before yield
--SKIPIF--
<?php require  __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine as co;
go(function () {
    try {
        echo "start\n";
        go(function(){
            try {
                echo "sub start\n";
                throw new Exception('sub coro Exception');
                co::sleep(0.5);
                echo "after go2 sleep\n";
            } catch (Exception $e) {
                echo 'Caught exception: ',  $e->getMessage(), "\n";
            }
        });
        echo "after go1 sleep\n";
    } catch (Exception $e) {
        echo 'Caught exception: ',  $e->getMessage(), "\n";
    }
});
    echo "end\n";
    
?>
--EXPECT--
start
sub start
Caught exception: sub coro Exception
after go1 sleep
end
