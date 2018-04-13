--TEST--
swoole_coroutine: coro invoke
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
use Swoole\Coroutine as co;
co::set(['trace_flags' => 1]);

co::create(function() {

    $function = new ReflectionFunction('foo');

    $function->invoke();
    echo "invoke end\n";

});

function foo() {
   co::sleep(0.5);
}


?>
--EXPECT--
invoke end
