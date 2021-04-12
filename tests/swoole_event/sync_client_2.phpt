--TEST--
swoole_event: sync client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;
use Swoole\Event;

swoole_async_set(['enable_coroutine' => false]);

$fp = new Client(SWOOLE_SOCK_TCP);
// async connect
$result = $fp->connect('www.qq.com', 80, 1, 1);

Assert::true($result);
Assert::eq($fp->errCode, SOCKET_EINPROGRESS);

Event::add($fp, null, function (Client $fp) {
    $fp->send("GET / HTTP/1.1\r\nHost: www.qq.com\r\n\r\n");
    Event::set($fp, function ($fp) {
        $resp = $fp->recv(8192);
        Assert::contains($resp, 'Location: https://www.qq.com/');

        Event::del($fp);
        $fp->close();

        echo "Done\n";
    }, null, SWOOLE_EVENT_READ);
}, SWOOLE_EVENT_WRITE);

Event::wait();
?>
--EXPECT--
Done
