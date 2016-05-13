<?php
$opt = getopt("c:n:k:");
print_r($opt);
if (empty($opt['c']) || empty($opt['n']))
{
    echo "examples:  php client.php -c 100 -n 10000" . PHP_EOL;
    return;
}
$clients = $opt['c'];
$count = $opt['n'];
$size = empty($opt['k']) ? 0 : $opt['k'];
require __DIR__ . "/WebSocketClient.php";
$host = '127.0.0.1';
$prot = 9501;

$client = new WebSocketClient($host, $prot);
$data = $client->connect();
//echo $data;
$data = "data";
if (!empty($size))
{
    $data = str_repeat("A", $size * 1024);
}
for ($i = 0; $i < $count; $i++)
{
    $client->send("hello swoole, number:" . $i . " data:" . $data);
    $recvData = "";
    //while(1) {
    $tmp = $client->recv();
    if (empty($tmp))
    {
        break;
    }
    $recvData .= $tmp;
    //}
    echo $recvData . "size:" . strlen($recvData) . PHP_EOL;
}
echo PHP_EOL . "======" . PHP_EOL;
sleep(1);
echo 'finish' . PHP_EOL;
