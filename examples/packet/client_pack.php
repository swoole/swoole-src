<?php
$cli = new swoole_client(SWOOLE_TCP);
if (!$cli->connect("127.0.0.1", 5900, -1))
{
    exit("connect failed. Error:{$cli->errCode}\r\n");
}

$msg_normal = "hello world.";
$msg_length = pack("N", strlen($msg_normal)) . $msg_normal;
$i = 0;
$times = 100;
while ($i < $times)
{
    $cli->send($msg_length);
    $i++;
    $data = $cli->recv(4, 1);
    $length = unpack("N", $data)[1];
    $msg = $cli->recv($length, 1);
    echo "receive:{$msg},len:{$length}\r\n";
}
$cli->close();

?>
