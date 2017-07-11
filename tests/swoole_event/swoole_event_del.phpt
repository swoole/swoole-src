--TEST--
global_function: swoole_event_del
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
$fp = stream_socket_client("tcp://www.qq.com:80", $errno, $errstr, 30);
fwrite($fp, "GET / HTTP/1.1\r\nHost: www.qq.com\r\n\r\n");

swoole_event_add($fp, function($fp) {
    $resp = fread($fp, 8192);
    //socket处理完成后，从epoll事件中移除socket
    swoole_event_del($fp);
    fclose($fp);
});
Swoole\Event::wait();
?>

--EXPECT--
