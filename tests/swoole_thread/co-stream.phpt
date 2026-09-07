--TEST--
swoole_thread: co stream
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Socket;
use Swoole\Thread;

$tm = new \SwooleTest\ThreadManager();
$tm->initFreePorts(increment: crc32(__FILE__) % 1000);

$tm->parentFunc = function () use ($tm) {
    $fp = stream_socket_server('tcp://127.0.0.1:' . $tm->getFreePort(), $errno, $errstr);
    Assert::notEmpty($fp);
    $thread = new Thread(__FILE__, $fp);
    var_dump('main thread');
    $thread->join();
    Assert::same($thread->getExitStatus(), 0);
};

$tm->childFunc = function ($fp) use ($tm) {
    var_dump('child thread');
    Co\run(function () use ($fp, $tm) {
        var_dump('child thread, co 0');
        $server = Socket::import($fp);
        Assert::isInstanceOf($server, Socket::class);
        Co\go(function () use ($tm) {
            var_dump('child thread, co 1');
            $client = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
            Assert::true($client->connect('127.0.0.1', $tm->getFreePort()));
            Assert::eq($client->recv(), "hello world\n");
            $client->close();
        });
        $conn = $server->accept();
        Assert::isInstanceOf($conn, Socket::class);
        $conn->sendAll("hello world\n");
        $conn->close();
        $server->close();
    });
};

$tm->run();
?>
--EXPECT--
string(11) "main thread"
string(12) "child thread"
string(18) "child thread, co 0"
string(18) "child thread, co 1"
