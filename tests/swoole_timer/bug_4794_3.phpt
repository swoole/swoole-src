--TEST--
swoole_timer: #4794 Timer::add() (ERRNO 505): msec value[0] is invalid
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;

Coroutine\run(function () {
    $client = stream_socket_client('tcp://www.qq.com:80', $errno, $errstr, 30);
    $events = Coroutine::waitEvent($client, SWOOLE_EVENT_READ | SWOOLE_EVENT_WRITE, 0.0001);
    Assert::eq($events, SWOOLE_EVENT_WRITE);
    fwrite($client, "GET / HTTP/1.1\r\nHost: www.qq.com\r\n\r\n");
    $events = Coroutine::waitEvent($client, SWOOLE_EVENT_READ);
    Assert::eq($events, SWOOLE_EVENT_READ);
    $response = fread($client, 8192);
    Assert::contains($response, 'www.qq.com');
});

echo "DONE\n";

?>
--EXPECT--
DONE
