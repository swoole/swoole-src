<?php
$client = new swoole_client(SWOOLE_SOCK_TCP);
if(!$client->connect('127.0.0.1', 9504))
{
    exit("connect failed\n");
}

for ($l=0; $l < 1; $l++) 
{ 
	$data = '';
    for($i=0; $i< 10; $i++) 
    {
        $len = rand(10000, 20000);
        echo "package length=".($len + 4)."\n";
        send_test3($client, $len);
    }
    //echo 'total send size:', strlen($data),"\n";
    //$client->send($data);
    sleep(1);
}

function send_test3($client, $len)
{
	$data = pack('n', $len + 4);
	$data .=  str_repeat('A', $len).rand(1000, 9999);

	$chunks = str_split($data, 4000);
	
	foreach($chunks as $ch)
	{
		$client->send($ch);
	}
	echo "package: ".substr($data, -4, 4)."\n";
}

function send_test2($client, $len)
{
	$data = pack('n', $len + 4);
    $data .=  str_repeat('A', $len).rand(1000, 9999);
	$client->send($data);
}

function send_test1($client, $len)
{
	$client->send(pack('n', $len + 4));
	usleep(10);
	$client->send(str_repeat('A', $len).rand(1000, 9999));
}
