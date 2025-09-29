--TEST--
swoole_event: write()
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_not_darwin();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

swoole_async_set([
    'enable_kqueue' => true,
]);

$fp = stream_socket_client("tcp://www.qq.com:80", $errno, $errstr, 30);

Swoole\Event::add($fp, function($fp) {
    $resp = fread($fp, 8192);

    Swoole\Event::del($fp);
    fclose($fp);

    echo "SUCCESS\n";

    Swoole\Timer::after(100, function () {
        posix_kill(posix_getpid(), SIGIO);
        Swoole\Timer::after(100, function () {
            echo "Done\n";
        });
    });
});

Swoole\Event::write($fp, "GET / HTTP/1.1\r\nHost: www.qq.com\r\n\r\n");

Swoole\Process::signal(SIGIO, function () {
    echo "SIGIO received\n";
    Swoole\Process::signal(SIGIO, null);
});

echo "Finish\n";
Swoole\Event::wait();
?>
--EXPECT--
Finish
SUCCESS
SIGIO received
Done
