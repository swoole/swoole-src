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
        $len = rand(100, 200);
        $data .= pack('N', $len + 4);
        $data .=  str_repeat('A', $len);
    }
    echo 'total send size:', strlen($data),"\n";
    $client->send($data);
    sleep(1);
}
