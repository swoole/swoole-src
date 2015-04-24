<?php
$serv = new swoole_server("127.0.0.1", 9501, SWOOLE_BASE);
$serv->set(array(
    'package_eof' => "\r\n\r\n",
    'open_eof_check' => true,
    'open_eof_split' => true,
    'worker_num' => 1,
    'dispatch_mode' => 1,
    'package_max_length' => 1024 * 1024 * 2, //2M
));
//$serv->on('connect', function ($serv, $fd) {
//    //echo "[#" . posix_getpid() . "]\tClient:Connect.\n";
//});
$serv->on('receive',
    function (swoole_server $serv, $fd, $from_id, $data)
    {
        echo "[#" . $serv->worker_pid . "] recv length=" . strlen($data) . "\n";
        $req = unserialize(trim($data));
        $respData = 'Welcome to swoole-server!';
        $response = implode("\r\n\r\n", [$respData, $respData, $respData]);
        $serv->send($fd, $response);
    });
//$serv->on('close', function ($serv, $fd) {
    //echo "[#" . posix_getpid() . "]\tClient: Close.\n";
//});
$serv->start();
