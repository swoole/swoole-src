<?php
go(function () {
    $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    $client->set(array(
        'socket_buffer_size' => 1024 * 512,
    ));
    if (!$client->connect('127.0.0.1', 9501, -1))
    {
        exit("connect failed. Error: {$client->errCode}\n");
    }
    $length = 0;
    $size = 1024 * 64;
    while (true)
    {
        $ret = $client->send(str_repeat('A', $size));
        if ($ret == false)
        {
            var_dump($ret);
            break;
        }
        $length += $size;
        echo "send $length success\n";
    }
    var_dump($client->errCode);
});

swoole_event_wait();