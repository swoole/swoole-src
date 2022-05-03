<?php
/**
 * User: lufei
 * Date: 2020/8/4
 * Email: lufei@swoole.com
 */

$client = new Swoole\Client(SWOOLE_SOCK_UDP);
if (!$client->connect('127.0.0.1', 9502, -1)) {
    exit("connect failed. Error: {$client->errCode}\n");
}
$client->send("hello world\n");
echo $client->recv();
$client->close();
