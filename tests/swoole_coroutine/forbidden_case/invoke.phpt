--TEST--
swoole_coroutine: coro invoke
--SKIPIF--
<?php require  __DIR__ . "/../../include/skipif.inc"; ?>
--FILE--
<?php
use Swoole\Coroutine as co;
co::set(['trace_flags' => 1]);

co::create(function() {
//execute ex
    $function = new ReflectionFunction('foo');

    $function->invoke();//execute_ex
    echo "invoke end\n";

});

function foo() {
   co::sleep(0.5);
}


?>
--EXPECT--
invoke end
