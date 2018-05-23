--TEST--
swoole_coroutine: coro array map
--SKIPIF--
<?php require __DIR__ . "/../../include/skipif.inc"; ?>
--FILE--
<?php
use Swoole\Coroutine as co;
co::create(function() {
    array_map("test",array("func start\n"));
    echo "co end\n";
});    
function test($p) {
    echo $p;
    co::sleep(1);
    echo "func end \n";
}
echo "main end\n";
?>
--EXPECT--
func start
main end
func end 
co end
