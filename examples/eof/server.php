<?php
$serv = new swoole_server("127.0.0.1", 9501, SWOOLE_BASE);
$serv->set(array(
    'package_eof' => "\r\n\r\n",
    'open_eof_check' => true,
    'open_eof_split' => true,
//    'worker_num' => 4,
    'dispatch_mode' => 3,
    'package_max_length' => 1024 * 1024 * 2, //2M
));
//$serv->on('connect', function ($serv, $fd) {
//    //echo "[#" . posix_getpid() . "]\tClient:Connect.\n";
//});
$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data)
{
    echo '#' . $serv->worker_id . " recv: " . strlen($data) . "\n";
    for ($i = 0; $i < 1000; $i++)
    {
        $resp = str_repeat('A', rand(10000, 50000)) . "\r\n\r\n";
        $serv->send($fd, $resp);
        if ($i % 100 == 1)
        {
            sleep(1);
            echo "send ".strlen($resp)." bytes\n";
        }
    }
});
//$serv->on('close', function ($serv, $fd) {
    //echo "[#" . posix_getpid() . "]\tClient: Close.\n";
//});
$serv->start();
