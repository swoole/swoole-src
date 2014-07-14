<?php
/**
 * UnitTests for swoole server.
 * This is just a client. Server see examples/server.php
 */

$client = new swoole_client(SWOOLE_TCP);

if (!$client->connect('127.0.0.1', 9501)) 
{
	echo "Step-1: failed. Error: connect to server failed.\n";
}
else
{
	if (!$client->send("hello"))
	{
		echo "Step-2: failed. Error: send to server failed.\n";
	}
	$data = $client->recv();
	if (!$data)
	{
		echo "Step-3: failed. Error: send to server failed.\n";
	}
	else if ($data != "Swoole: hello")
	{
		echo "Step-4: failed. Error: recv error data.\n";
	}
}

if (!$client->close())
{
	echo "Step-8: failed. Error: close failed.\n";
}
echo "UnitTest Finish.\n";
