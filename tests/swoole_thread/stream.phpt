--TEST--
swoole_thread: stream
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
    $serverQueue = new Queue();
    $connQueue = new Queue();
    $fp = stream_socket_server('tcp://127.0.0.1:' . $tm->getFreePort(), $errno, $errstr);
    $serverQueue->push($fp);
    fclose($fp);
    var_dump('main thread');
    $thread = new Thread(__FILE__, $serverQueue, $connQueue, 0);
    $client = stream_socket_client('tcp://127.0.0.1:' . $tm->getFreePort(), $errno, $errstr);
    Assert::notEmpty($client);
    $data = fread($client, 8192);
    Assert::eq($data, "hello world\n");
    fclose($client);
    $thread->join();
};

$tm->childFunc = function ($serverQueue, $connQueue, $id) {
    if ($id === 0) {
        var_dump('child thread 0');
        $fp = $serverQueue->pop();
        $conn = stream_socket_accept($fp, -1);
        $connQueue->push($conn);
        fclose($conn);
        fclose($fp);
        $thread = new Thread(__FILE__, $connQueue, $connQueue, 1);
        $thread->join();
    } else {
        var_dump('child thread 1');
        $conn = $connQueue->pop();
        fwrite($conn, "hello world\n");
        fclose($conn);
    }
};

$tm->run();
?>
--EXPECT--
string(11) "main thread"
string(14) "child thread 0"
string(14) "child thread 1"
