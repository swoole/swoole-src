--TEST--
swoole_coroutine: coro array map
--SKIPIF--
<?php require __DIR__ . "/../../include/skipif.inc"; ?>
--FILE--
<?php

use Swoole\Coroutine as co;

co::set(['trace_flags' => 1]);

co::create(function() {
    array_map("test",array("param\n"));
    echo "map end\n";
});

function test($p) {
    echo $p;
    co::sleep(0.5);
}
?>
--EXPECT--
param
map end