<?php
function send(swoole_client $cli)
{
    $data = array(
        'str1' => str_repeat('A', rand(100000, 900000)),
        'str2' => str_repeat('B', rand(100000, 900000)),
        'str3' => str_repeat('C', rand(10000, 90000)),
    );

    $data['int1'] = rand(100000, 999999);

    $sendStr = serialize($data);
    $sendData = pack('N', strlen($sendStr)) . $sendStr;
    $cli->send($sendData);
    echo "send length=" . strlen($sendData) . ", SerId={$data['int1']}\n";
}

$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC); //异步非阻塞

$client->set(array(
    'open_length_check'     => 1,
    'package_length_type'   => 'N',
    'package_length_offset' => 0,       //第N个字节是包长度的值
    'package_body_offset'   => 4,       //第几个字节开始计算长度
    'package_max_length'    => 2000000,  //协议最大长度
));

$client->on("connect", function(swoole_client $cli) {
    send($cli);
});

$client->on("receive", function (swoole_client $cli, $data) {
    $resp = unserialize(substr($data, 4));
    echo "recv length=" . strlen($data) . ", SerId={$resp['int1']}\n".str_repeat('-', 60)."\n";
    $cli->close();
//    sleep(1);
    //usleep(200000);
    //send($cli);
});

$client->on("error", function(swoole_client $cli){
    echo "error\n";
});

$client->on("close", function(swoole_client $cli){
    echo "Connection close\n";
});

$client->connect('127.0.0.1', 9501);

