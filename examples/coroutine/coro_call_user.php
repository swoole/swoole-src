<?php
use Swoole\Coroutine as co;
co::set(['trace_flags' => 1]);

co::create(function() {

	call_user_func_array("test",["hhh"]);
	echo "coro func client end \n";

});

function test($a)
{
	echo "call user func $a";
	$client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
	$res = $client->connect('127.0.0.1', 9501, 10);
        var_dump($res);
	if ($res)
	{
	    echo("connect success. Error: {$client->errCode}\n");
	}
	$res = $client->send("hello");
	echo "send res:".var_export($res ,1)."\n";
	$data = $client->recv();
    	echo "recv data".var_export($data ,1)."\n";
}
echo "111\n";


