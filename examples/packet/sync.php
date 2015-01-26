<?php
$cli = new swoole_client(SWOOLE_TCP | SWOOLE_PACKET);
if (!$cli->connect("127.0.0.1", 5900, -1))
{
    exit("connect failed. Error:{$cli->errCode}\r\n");
}

$msg_normal = "hello world";
$i = 0;
while ($i < 5)
{
    $cli->send($msg_normal);
    $i++;
    $data = $cli->recv();
    echo "recieve:{$data},len=" . strlen($data) . "\r\n";
}
$cli->close();
