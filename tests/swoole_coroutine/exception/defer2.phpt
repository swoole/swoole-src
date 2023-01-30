--TEST--
swoole_coroutine/exception: defer 2
--SKIPIF--
<?php require  __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Coroutine;

register_shutdown_function(function (){
    echo "shutdown\n";
});

Co\run(function () {
    echo "co-1 begin\n";

    Coroutine::create(static function () {
        echo "co-2 begin\n";
        Coroutine::defer(static function () {
            echo "never execute\n";
        });
        Coroutine::defer(static function () {
            echo "defer task begin\n";
            throw new Exception();
            echo "defer task end\n";
        });
        echo "co-2 end\n";
    });

    echo "co-1 end\n";
});
echo "done\n";
?>
--EXPECTF--
co-1 begin
co-2 begin
co-2 end
defer task begin

Fatal error: Uncaught Exception in %s:%d
Stack trace:
#0 [internal function]: {closure}(NULL)
#1 {main}
  thrown in %s on line %d
shutdown
