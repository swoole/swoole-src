--TEST--
swoole_event: swoole_event_isset
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$fp = stream_socket_client("tcp://www.qq.com:80", $errno, $errstr, 30);
fwrite($fp, "GET / HTTP/1.1\r\nHost: www.qq.com\r\n\r\n");

swoole_event_add($fp, function ($fp) {
    $resp = fread($fp, 8192);
    //socket处理完成后，从epoll事件中移除socket
    swoole_event_del($fp);
    fclose($fp);
});

Assert::true(swoole_event_isset($fp, SWOOLE_EVENT_READ));
Assert::false(swoole_event_isset($fp, SWOOLE_EVENT_WRITE));
Swoole\Event::wait();
?>
--EXPECT--
