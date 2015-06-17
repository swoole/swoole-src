<?php
require __DIR__.'/TestServer.php';

class EofServer extends TestServer
{
    function onReceive($serv, $fd, $from_id, $data)
    {
        $pkg = unserialize(rtrim($data));
        if ($pkg['index'] % 1000 == 0)
        {
            echo "#{$pkg['index']} recv package. sid={$pkg['sid']}, length=" . strlen($data) . "\n";
        }
        if (!isset($pkg['index']))
        {
            exit;
        }
        if ($pkg['index'] > self::PKG_NUM)
        {
            echo "invalid index #{$pkg['index']}\n";
        }
        $this->index[$pkg['index']] = true;
    }
}

$serv = new EofServer();
$serv->set([
    'package_eof' => "\r\n\r\n",
    'open_eof_check' => true,
    'open_eof_split' => true,
    //'worker_num' => 4,
    'dispatch_mode' => 3,
    'package_max_length' => 1024 * 1024 * 2, //2M
]);
$serv->start();
