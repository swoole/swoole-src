--TEST--
swoole_event: Swoole\Event::set
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$fp = stream_socket_client("tcp://www.qq.com:80", $errno, $errstr, 30);

function write_callback($fp) {
    $resp = fread($fp, 8192);

    //socket处理完成后，从epoll事件中移除socket
    Swoole\Event::del($fp);
    fclose($fp);

    echo "read_callback:SUCCESS\n";
}

Swoole\Event::add($fp, function($fp) {
    $resp = fread($fp, 8192);

    //socket处理完成后，从epoll事件中移除socket
    Swoole\Event::del($fp);
    fclose($fp);

    echo "SUCCESS\n";
});

#设置写事件回调函数，这会替换掉原有的写事件回调函数
Swoole\Event::set($fp, null, 'write_callback', SWOOLE_EVENT_WRITE);

Swoole\Event::write($fp, "GET / HTTP/1.1\r\nHost: www.qq.com\r\n\r\n");
echo "Finish\n";
Swoole\Event::wait();
?>
--EXPECT--
Finish
read_callback:SUCCESS
