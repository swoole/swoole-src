<?php
$ifs = swoole_get_local_ip();
if (isset($ifs['eth0']))
{
	$server_ip = $ifs['eth0'];
}
else
{
	die("Step-0 failed. Error: swoole_get_local_ip() failed.");
}
echo "-------------------------------------------------------------\n";
echo "Swoole Unit Tests. ServerIP: {$server_ip}\n";
echo "-------------------------------------------------------------\n";
/**
 * UnitTests for swoole server.
 * This is just a client. Server see examples/server.php
 */
$i = 0;
$client = new swoole_client(SWOOLE_TCP);

if (!$client->connect($server_ip, 9501)) 
{
	echo "Step-".$i++.": failed. Error: connect to server failed.\n";
}
else
{
	if (!$client->send("hello"))
	{
		echo "Step-".$i++.": failed. Error: send to server failed.\n";
	}
	$data = $client->recv();
	if (!$data)
	{
		echo "Step-".$i++.": failed. Error: send to server failed.\n";
	}
	else if ($data != "Swoole: hello")
	{
		echo "Step-".$i++.": failed. Error: recv error data.\n";
	}
	else
	{
		echo "TCP-Test-OK\n";
	}
}

if (!$client->close())
{
	echo "Step-".$i++.": failed. Error: close failed.\n";
}
echo "-------------------------------------------------------------\n";
$client = new swoole_client(SWOOLE_UDP);
$client->connect($server_ip, 9502);
$client->send("hello");
$data = $client->recv();
if (!$data)
{
	echo "Step-".$i++.": failed. Error: send to server failed.\n";
}
else if ($data != "Swoole: hello")
{
	echo "Step-".$i++.": failed. Error: recv error data.\n";
}
else
{
	echo "UDP-Test-OK\n";
}
echo "-------------------------------------------------------------\n";
echo "UnitTest Finish.\n";
