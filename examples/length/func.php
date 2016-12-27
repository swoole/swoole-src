<?php
$serv = new swoole_server("127.0.0.1", 9501);

$serv->set(array(
    'open_length_check' => true,
    'dispatch_mode' => 1,
    'package_length_func' => function ($data) {
        if (strlen($data) < 8) {
            return 0;
        }
        $length = intval(trim(substr($data, 0, 8)));
        if ($length <= 0) {
            return -1;
        }
        return $length + 8;
    },
    'package_max_length' => 2000000,  //协议最大长度
));

$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data)
{
    var_dump($data);
    echo "#{$serv->worker_id}>> received length=" . strlen($data) . "\n";
});

$serv->start();
