<?php
use Swoole\Coroutine as co;
co::set(['trace_flags' => 1]);

co::create(function() {
    echo "co func start\n";
    $name = "call_user_func";
    $ret = $name("test","test\n");
	echo "co func end ret:{$ret}\n";
});

function test($params)
{
    echo "func params:$params";
    co::sleep(1);
    echo "func end\n";
    return "test return\n";
}
echo "main script last\n";
