--TEST--
swoole_coroutine/exception: throw in destructor
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
    Coroutine::create([new class {
        public function test() {
            echo 'test', PHP_EOL;
        }
        public function __destruct() {
            throw new Exception();
        } 
    }, 'test']);

    echo "co-1 end\n";
});
echo "done\n";
?>
--EXPECTF--
co-1 begin
test

Fatal error: Uncaught Exception in %s:%d
Stack trace:
#0 %s(%d): class@anonymous->__destruct()
%A
  thrown in %s on line %d
shutdown
