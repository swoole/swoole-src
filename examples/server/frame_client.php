<?php
$client = new swoole_client(SWOOLE_TCP | SWOOLE_ASYNC);
$client->count = 0;

function sendPackage(swoole_client $cli)
{
    $data = array(
        'str1' => str_repeat('A', rand(1000, 9000)),
        'str2' => str_repeat('B', rand(1000, 9000)),
        'str3' => str_repeat('C', rand(1000, 9000)),
    );

    $data['int1'] = rand(100000, 999999);

    $sendStr = serialize($data);
    $sendData = pack('N', strlen($sendStr)) . $sendStr;
    echo "send length=" . strlen($sendData) . ", SerId={$data['int1']}\n";

    $cli->send($sendData);
}

$client->set(array(
    'open_length_check'     => 1,
    'dispatch_mode'         => 1,
    'worker_num'            => 4,
    'package_length_type'   => 'N',
    'package_length_offset' => 0,       //第N个字节是包长度的值
    'package_body_offset'   => 4,       //第几个字节开始计算长度
    'package_max_length'    => 2000000,  //协议最大长度
));


$client->on('connect', function (swoole_client $cli) {
    echo "Connected.\n";
    sendPackage($cli);
});

$client->on('receive', function (swoole_client $cli, $data) {
    $req = unserialize(substr($data, 4));
    echo ">> received length=".strlen($data).", SerId: {$req['int1']}\n";

    $cli->count ++;

    if ($cli->count > 10)
    {
        $cli->close();
    }

    swoole_timer_after(1000, function() use ($cli) {
        sendPackage($cli);
    });
});

$client->on('close', function ($cli) {
    echo "Client: Close.\n";
});

$client->on('error', function ($cli) {
    echo "connect failed.\n";
});

$client->connect('127.0.0.1', 9501);
