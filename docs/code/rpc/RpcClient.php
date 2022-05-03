<?php
/**
 * User: lufei
 * Date: 2020/8/6
 * Email: lufei@swoole.com
 */

include __DIR__ . '/Tools.php';

$client = new Swoole\Client(SWOOLE_SOCK_TCP);
//$client->set(
//    [
//        'open_length_check' => true, // 打开包长检测
//        'package_length_type' => 'N', // 长度值的类型，与 PHP 的 pack 函数一致。
//        'package_length_offset' => 0, // 第N个字节是包长度的值
//        'package_body_offset' => 4, // 第几个字节开始计算长度
//    ]
//);
if (!$client->connect('127.0.0.1', 9502, -1)) {
    exit("connect failed. Error: {$client->errCode}\n");
}
$send = [
    'class' => 'User',
    'method' => 'getList',
    'params' => [
        'uid' => 1,
        'type' => 2,
    ],
];
$client->send(\Swoole\Rpc\Tools::pack($send));
$recv = $client->recv();
var_dump($recv, \Swoole\Rpc\Tools::unpack($recv));
$client->close();
