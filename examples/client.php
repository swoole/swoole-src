<?php
$clients = array();
for($i=0; $i< 2; $i++)
{
    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
    $ret = $client->connect('127.0.0.1', 9501, 0.5, 0);
    if(!$ret)
    {
        echo "Connect Server fail.errCode=".$client->errCode;
    }
    else
    {
    	$client->send("HELLO WORLD\n");
    	$clients[$client->sock] = $client;
    }
}

while(!empty($clients))
{
	$write = $error = array();
	$read = array_values($clients);
	$n = swoole_client_select($read, $write, $error, 0.6);
	if($n > 0)
	{
		foreach($read as $index=>$c)
		{
			echo "Recv #{$c->sock}: ".$c->recv()."\n";
			unset($clients[$c->sock]);
		}
	}
}
/*
$client = new swoole_client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_SYNC); //同步阻塞
$client->connect('127.0.0.1', 9501, 0.5, 0);
$mem_start = memory_get_peak_usage();
for($i=0; $i< 1; $i++){
    $client->send("hello world-{$i}");
    $data = $client->recv(1024, 0);
}
echo "Mem User=".(memory_get_peak_usage() - $mem_start)."\n";
$client->close();
*/
/*
$client = new swoole_client(SW_SOCK_TCP, SW_SOCK_ASYNC); //异步非阻塞
$client->connect('127.0.0.1', 9501, 0.5, 0);

$client->on("connect", function($cli){
    $cli->send("hello world\n");
    echo "onConnect";
});

$client->on("receive", function($cli, $data){
    echo "onReceive: $data\n";
});

$client->on("close", function($cli){
    echo "onClose: $data\n";
});
*/