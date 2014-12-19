<?php
$client = new swoole_client(SWOOLE_SOCK_TCP);
if(!$client->connect('127.0.0.1', 9501))
{
    exit("connect fail\n");
}

$data = array(
    'str1' => str_repeat('A', 10240),
    'str2' => str_repeat('B', 10240),
    'str3' => str_repeat('C', 10240),
);

for ($l=0; $l < 1; $l++)
{
    $datas = array();
    for($i=0; $i< 1000; $i++)
    {
        $data['int1'] = rand(100000, 999999);
        $sendStr = serialize($data);
        $client->send( pack('N', strlen($sendStr)). $sendStr);
        echo "send length=".strlen($sendStr).", SerId={$data['int1']}\n";
    }
    sleep(1);
}
