<?php
$client = new swoole_client(SWOOLE_SOCK_TCP);
$client->set(array(
    'kernel_socket_buffer_size' => 65536,
));

if (!$client->connect('127.0.0.1', 9501, -1))
{
    exit("connect failed. Error: {$client->errCode}\n");
}

var_dump($client->getsockname());

$client->send("start\n");
$length = 0;

while(true)
{
    $data = $client->recv(65536);
    if ($data == false) {
        break;
    }
    $length += strlen($data);
    echo "recv ".$length." bytes\n";
    usleep(100000);
}
