--TEST--
swoole_coroutine: coro invoke
--SKIPIF--
<?php require  __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine as co;
co::create(function() {
    $function = new ReflectionFunction('foo');
    $function->invoke();
    echo "co end\n";
});
function foo() {
   echo "func start\n";
   co::sleep(0.5);
   echo "func end\n";
}
echo "main end\n";
?>
--EXPECT--
func start
main end
func end
co end
