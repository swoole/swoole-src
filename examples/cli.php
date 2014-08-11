<?php

//$send = str_repeat("A", 956).str_repeat("B", 566).str_repeat("C", 900);
//$client->send(str_repeat("A", 956));
//$client->send(str_repeat("B", 566));
//$client->send(str_repeat("C", 900));
// pcntl_fork();
function test_client(){
$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
if(!$client->connect('127.0.0.1', 9501))
{
	exit("connect fail\n");
}
if(empty($argv[1]))
{
	$loop = 1;
}
else
{
	$loop = intval($argv[1]);
}

for($i=0; $i<$loop; $i++)
{
    $client->send(str_repeat("A", 600).$i);
    $data = $client->recv(7000, 0);
    if($data === false)
    {
        echo "recv fail\n";
        break;
    }
    //echo "recv[$i]",$data,"\n";
}

//echo "len=".strlen($data)."\n";
// $client->send("HELLO\0\nWORLD");
// $data = $client->recv(9000, 0);
$client->close();
var_dump($data);
unset($client);
}
test_client();
sleep(1);
