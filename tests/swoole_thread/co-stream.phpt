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

use Swoole\Runtime;
use Swoole\Thread;
use Swoole\Thread\Queue;

$tm = new \SwooleTest\ThreadManager();
$tm->initFreePorts(increment: crc32(__FILE__) % 1000);

$tm->parentFunc = function () use ($tm) {
    Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
    Co\run(function () use ($tm) {
        $queue = new Queue();
        $fp = stream_socket_server('tcp://127.0.0.1:' . $tm->getFreePort(), $errno, $errstr);
        $queue->push($fp);
        $thread = new Thread(__FILE__, $queue);
        var_dump('main thread');
        $thread->join();
    });
};

$tm->childFunc = function ($queue) use ($tm) {
    var_dump('child thread');
    $fp = $queue->pop();
    Co\run(function () use ($fp, $tm) {
        var_dump('child thread, co 0');
        Co\go(function () use ($tm) {
            var_dump('child thread, co 1');
            $client = stream_socket_client('tcp://127.0.0.1:' . $tm->getFreePort(), $errno, $errstr);
            Assert::notEmpty($client);
            $data = fread($client, 8192);
            Assert::eq($data, "hello world\n");
            fclose($client);
        });
        $conn = stream_socket_accept($fp, -1);
        fwrite($conn, "hello world\n");
        fclose($conn);
        fclose($fp);
    });
};

$tm->run();
?>
--EXPECT--
string(11) "main thread"
string(12) "child thread"
string(18) "child thread, co 0"
string(18) "child thread, co 1"
