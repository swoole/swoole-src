<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(array(
    'package_eof' => "\r\n\r\n",
    'open_eof_check' => true,
    'package_max_length' => 1024 * 1024 * 2, //2M
));
$serv->on('connect', function ($serv, $fd) {
    //echo "[#" . posix_getpid() . "]\tClient:Connect.\n";
});
$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
    //$req = unserialize(trim($data));
    //echo $req['name'] . "\n";
    //echo "content_length: " . strlen($data) . "\n";
    $respData = '<h1>Welcome to swoole-server!</h1>';
    $response = implode("\r\n", array(
        'HTTP/1.1 200 OK',
        'Cache-Control: must-revalidate,no-cache',
        'Content-Language: zh-CN',
        'Server: swoole-'.SWOOLE_VERSION,
        'Content-Type: text/html',
        'Connection: keep-alive',
        'Content-Length: ' . strlen($respData),
        '',
        $respData));
    $serv->send($fd, $response);
});
$serv->on('close', function ($serv, $fd) {
    //echo "[#" . posix_getpid() . "]\tClient: Close.\n";
});
$serv->start();
