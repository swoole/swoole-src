--TEST--
swoole_coroutine: coro call user func
--SKIPIF--
<?php require __DIR__ . "/../../include/skipif.inc"; ?>
--FILE--
<?php

use Swoole\Coroutine as co;

co::set(['trace_flags' => 1]);

co::create(function() {
    $name = "call_user_func";
    $return = $name("test");
    echo "call user\n";
});

function test() {
    echo "start\n";
    co::sleep(0.5);
    echo "exit\n";
}
?>
--EXPECT--
start
call user
exit
