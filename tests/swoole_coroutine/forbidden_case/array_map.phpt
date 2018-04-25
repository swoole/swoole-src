--TEST--
swoole_coroutine: coro array map
--SKIPIF--
<?php require __DIR__ . "/../../include/skipif.inc"; ?>
--FILE--
<?php
use Swoole\Coroutine as co;

co::create(function() {
    array_map("test",array("func param\n"));
    echo "co flow end\n";
});
    
function test($p) {
    echo $p;
    co::sleep(1);
    echo "map func end \n";
}
echo "main end\n";
?>
--EXPECT--
func param
co flow end
main end
map func end
