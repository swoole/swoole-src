<?php
$serv = new swoole_server("127.0.0.1", 9501);

$serv->set(array(
    'dispatch_func' => function ($serv, $fd, $type, $data) {
        var_dump($fd, $type, $data);
        return intval($data[0]);
    },
));

$serv->on('receive', function (swoole_server $serv, $fd, $threadId, $data)
{
    var_dump($data);
    echo "#{$serv->worker_id}>> received length=" . strlen($data) . "\n";
});

$serv->start();
