--TEST--
swoole_coroutine/forbidden_case: coro array map
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine as co;
co::create(function() {
    array_map("test",array("func start\n"));
    echo "co end\n";
});
function test($p) {
    echo $p;
    co::sleep(.001);
    echo "func end\n";
}
echo "main end\n";
?>
--EXPECT--
func start
main end
func end
co end
