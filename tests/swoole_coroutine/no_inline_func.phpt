--TEST--
swoole_coroutine: coro not inline function
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;

echo "start\n";
co::create(function () {
    $ret = test();
    echo $ret;
});
function test()
{
    echo "start func\n";
    co::sleep(0.001);
    echo "end func\n";
    return "return func params\n";
}
echo "end\n";
?>
--EXPECT--
start
start func
end
end func
return func params
