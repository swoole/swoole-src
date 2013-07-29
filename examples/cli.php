<?php

//$send = str_repeat("A", 956).str_repeat("B", 566).str_repeat("C", 900);
//$client->send(str_repeat("A", 956));
//$client->send(str_repeat("B", 566));
//$client->send(str_repeat("C", 900));
// pcntl_fork();

$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
if(!$client->connect('127.0.0.1', 9501))
{
	exit("connect fail\n");
}
// for($i=0; $i<100; $i++)
// {
//     $client->send(str_repeat("A", 32).$i);
//     $data = $client->recv(9000, 0);
//     if($data === false)
//     {
//         echo "recv fail\n";
//         break;
//     }
//     echo "recv[$i]",$data,"\n";
// }

//echo "len=".strlen($data)."\n";
$client->send("HELLO\0\nWORLD");
$data = $client->recv(9000, 0);
$client->close();
var_dump($data);
