--TEST--
swoole_windows: event stdin
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Event;
use Swoole\Timer;

Co\run(function (){
    Timer::after(100, function () {
        fwrite(STDOUT, "hello swoole\n");
    });

    $client = stream_socket_client('tcp://'.TEST_DOMAIN_3.':80', $errno, $errstr);
    if (!$client) {
        echo "connect failed. Error: {$errno} {$errstr}\n";
    } else {
        fwrite($client, "GET / HTTP/1.1\r\nHost: ".TEST_DOMAIN_3."\r\n\r\n");
        Event::add($client, function ($fp) {
            $resp = fread($fp, 1024);
            Event::del($fp);
            Assert::contains($resp, 'HTTP/1.1 301 Moved Permanently');
            echo "DONE\n";
        }, null, SWOOLE_EVENT_READ);
    }
});
?>
--EXPECT--
DONE
hello swoole
