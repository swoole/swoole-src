--TEST--
swoole_thread: stream as a thread argument
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;
use Swoole\Thread\Queue;

$tm = new \SwooleTest\ThreadManager();
$tm->initFreePorts(increment: crc32(__FILE__) % 1000);

$tm->parentFunc = function () use ($tm) {
    $fp = stream_socket_server('tcp://127.0.0.1:' . $tm->getFreePort(), $errno, $errstr);
    $thread = new Thread(__FILE__, $fp, 0);
    var_dump('main thread');
    $thread->join();
};

$tm->childFunc = function ($fp, $id) use ($tm) {
    if ($id === 0) {
        var_dump('child thread 0');
        $thread = new Thread(__FILE__, $fp, 1);
        $conn = stream_socket_accept($fp, -1);
        fwrite($conn, "hello world\n");
        fclose($conn);
        fclose($fp);
        $thread->join();
    } else {
        var_dump('child thread 1');
        $client = stream_socket_client('tcp://127.0.0.1:' . $tm->getFreePort(), $errno, $errstr);
        Assert::notEmpty($client);
        $data = fread($client, 8192);
        Assert::eq($data, "hello world\n");
        fclose($client);
    }
};

$tm->run();
?>
--EXPECT--
string(11) "main thread"
string(14) "child thread 0"
string(14) "child thread 1"
