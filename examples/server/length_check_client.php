<?php
$client = new swoole_client(SWOOLE_SOCK_TCP);
if(!$client->connect('127.0.0.1', 9501))
{
    exit("connect failed\n");
}

for($i=0; $i< 10; $i++)
{
    $data = array(
        'str1' => str_repeat('A', rand(1000, 9000)),
        'str2' => str_repeat('B', rand(1000, 9000)),
        'str3' => str_repeat('C', rand(1000, 9000)),
    );

    $data['int1'] = rand(100000, 999999);

    $sendStr = serialize($data);
    $sendData = pack('N', strlen($sendStr)). $sendStr;
    $client->send($sendData);
    echo "send length=".strlen($sendData).", SerId={$data['int1']}\n";
}
sleep(2);

