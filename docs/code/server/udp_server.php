<?php
/**
 * User: lufei
 * Date: 2020/8/4
 * Email: lufei@swoole.com
 */

//创建Server对象，监听 127.0.0.1:9502 端口，类型为 SWOOLE_SOCK_UDP
$server = new Swoole\Server('127.0.0.1', 9502, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);

//监听数据接收事件
$server->on('Packet', function ($server, $data, $clientInfo) {
    var_dump($clientInfo);
    $server->sendto($clientInfo['address'], $clientInfo['port'], 'Server：' . $data);
});

//启动服务器
$server->start();
