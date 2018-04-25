<?php
use Swoole\Coroutine as co;
co::set(['trace_flags' => 1]);

co::create(function() {
    echo "co func start\n";
	call_user_func_array("test",["test\n"]);
	echo "co func end \n";
});

function test($params)
{
    echo "func $params";
    co::sleep(1);
    echo "func end\n";
}
echo "main script last\n";
