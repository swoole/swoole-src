--TEST--
global_function: swoole_event_write

--FILE--
<?php
$fp = stream_socket_client("tcp://www.qq.com:80", $errno, $errstr, 30);

swoole_event_add($fp, function($fp) {
    $resp = fread($fp, 8192);

    //socket处理完成后，从epoll事件中移除socket
    swoole_event_del($fp);
    fclose($fp);

    echo "SUCCESS\n";
});

swoole_event_write($fp, "GET / HTTP/1.1\r\nHost: www.qq.com\r\n\r\n");

echo "Finish\n";
?>

--EXPECT--
Finish

SUCCESS
