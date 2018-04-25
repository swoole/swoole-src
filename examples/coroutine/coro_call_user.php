<?php
use Swoole\Coroutine as co;
co::set(['trace_flags' => 1]);

co::create(function() {
	call_user_func_array("test",["test\n"]);
	echo "main func client end \n";
});

function test($a)
{
	echo "func $a";
	$client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
	$res = $client->connect('127.0.0.1', 9501, 10);
	echo(__FUNCTION__." connect res :".var_export($res,1)."\n");
	call_user_func_array("test2",["test2\n"]);
}

function test2($a)
{
	call_user_func_array("test3",["test3\n"]);
	echo "func $a";
	$client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
	$res = $client->connect('127.0.0.1', 9501, 10);
 	echo(__FUNCTION__." connect res :".var_export($res,1)."\n");
	call_user_func('test4', "test4\n");
}

function test3($a)
{
	echo "func $a";
	$client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
	$res = $client->connect('127.0.0.1', 9501, 10);
	sleep(1);
 	echo(__FUNCTION__." connect res :".var_export($res,1)."\n");
}

function test4($a)
{
	echo "func $a";
	$client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
	$res = $client->connect('127.0.0.1', 9501, 10);
	sleep(1);
 	echo(__FUNCTION__." connect res :".var_export($res,1)."\n");
}

echo "main script last\n";
