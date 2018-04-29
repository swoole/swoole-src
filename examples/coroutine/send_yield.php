<?php
$serv = new Swoole\Server("0.0.0.0", 9501, SWOOLE_BASE);
$serv->set(array(
    'worker_num' => 1,
    'send_yield' => true,
    'socket_buffer_size' => 512 * 1024,
    'kernel_socket_buffer_size' => 65536,
));
$serv->on('connect', function ($serv, $fd) {
    echo "Client:Connect.\n";
});
$serv->on('receive', function ($serv, $fd, $from_id, $data) {
    $length = 0;
    $size = 1024 * 128;
    while (true)
    {
        $ret = $serv->send($fd, str_repeat('A', $size));
        if ($ret == false) {
            break;
        }
        $length += $size;
        echo "send $length success\n";
    }
});
$serv->on('close', function ($serv, $fd) {
    echo "Client: Close.\n";
});
$serv->start();
