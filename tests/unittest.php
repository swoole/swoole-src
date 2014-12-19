<?php
class Console
{
	const RED = "31";
	const GREEN = "32";
	const LINE_N = 56;
	
	static function put($msg, $failed = false, $die = false)
	{
		$color = $failed ? self::RED : self::GREEN;
		$status = $failed ? "Failed" : "Success";
		$space = str_repeat(' ', self::LINE_N - strlen($msg));
		echo "{$msg}{$space}\033[{$color}m [{$status}]\033[0m\n";
		if ($failed and $die) die;
	}
}

echo "------------------------------------------------------------------\n";
echo "Swoole Unit Tests. Version 1.0.0\n";
echo "Author: Han Tianfeng.\n";
echo "CopyRight: Swoole-Team.\n";
echo "------------------------------------------------------------------\n";

Console::put("extension_loaded('swoole')", !extension_loaded('swoole'), true);
Console::put("swoole_get_local_ip()", !is_array(swoole_get_local_ip()));
Console::put("swoole_version()", !is_string(swoole_version()));

if (!class_exists('swoole_process')) 
{
	Console::put("no have swoole_process", true, true);
}

$server = new swoole_process(function($process) {
	$php = $_SERVER['_'];
	return $process->exec($php, array(__DIR__."/../examples/server.php", 'daemon'));
}, false, false);

if (!$server->start()) 
{
	Console::put("Server start failed.", true, true);
}
usleep(200000);
register_shutdown_function(function() {
	global $server;
	if (swoole_process::kill($server->pid, SIGTERM)) 
	{
		Console::put("swoole_process::kill()");
		$status = swoole_process::wait();
		Console::put("swoole_process::wait()", !($status['pid'] == $server->pid));
	}
	else
	{
		Console::put("swoole_process::kill()", true);
	}
	echo "------------------------------------------------------------------\n";;
	echo "Swoole UnitTest Finish.\n";
});

/**
 * UnitTests for swoole server.
 * This is just a client. Server see examples/server.php
 */
$client = new swoole_client(SWOOLE_TCP);

if (!$client->connect('127.0.0.1', 9501)) 
{
	Console::put("swoole_client[TCP]->connect().", true, true);
}
else
{
	Console::put("swoole_client[TCP]->connect()");
	if (!$client->send("hello"))
	{
		Console::put("swoole_client[TCP]->send()", true);
	}
	else 
	{
		Console::put("swoole_client[TCP]->send()");
		$data = $client->recv();
		
		if (!$data)
		{
			Console::put("swoole_client[TCP]->send()", true);
		}
		else if ($data != "Swoole: hello")
		{
			Console::put("Echo Service on TCP", true);
		}
		else
		{
			Console::put("Echo Service on TCP");
		}
	}
	//上面已经测试过通道，所下面就不再重复检测
	$client->send("task");
	$data = $client->recv();
	Console::put("swoole_server->task()", !$data or $data != 'taskok');
	
	$client->send("taskwait");
	$data = $client->recv();
	Console::put("swoole_server->taskwait()", !$data or $data != 'taskwaitok');
}
Console::put("swoole_client->close()", !$client->close());
echo "------------------------------------------------------------------\n";
$client = new swoole_client(SWOOLE_UDP);
Console::put("swoole_client[UDP]->recv()", !$client->connect('127.0.0.1', 9502));
Console::put("swoole_client[UDP]->recv()", !$client->send("hello"));
$data = $client->recv();

if (!$data)
{
	Console::put("swoole_client[UDP]->recv()", true);
}
else if ($data != "Swoole: hello")
{
	Console::put("Echo Service on UDP", true);
}
else
{
	Console::put("Echo Service on UDP");
}
echo "------------------------------------------------------------------\n";
Console::put("test failed", true);

