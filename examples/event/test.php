<?php
$fp = stream_socket_client("tcp://127.0.0.1:9501", $errno, $errstr, 30);
fwrite($fp, "HELLO world");

Swoole\Event::add($fp, function ($fp) {
    echo fread($fp, 1024)."\n";
    Swoole\Event::del($fp);
    fclose($fp);
});
