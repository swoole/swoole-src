--TEST--
swoole_thread: php_socket
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
use SwooleTest\ThreadManager;

$tm = new ThreadManager();
$tm->initFreePorts(increment: crc32(__FILE__) % 1000);

$tm->parentFunc = function () use ($tm) {
    $queue = new Queue();
    $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    socket_set_option($sock, SOL_SOCKET, SO_REUSEADDR, 1);
    socket_bind($sock, '127.0.0.1', $tm->getFreePort());
    $queue->push($sock);
    $thread = new Thread(__FILE__, $queue, 0);
    var_dump('main thread');
    $thread->join();
};

$tm->childFunc = function ($queue, $id) use ($tm) {
    if ($id === 0) {
        var_dump('child thread 0');
        $svr_sock = $queue->pop();
        socket_listen($svr_sock, 128);
        $thread = new Thread(__FILE__, $queue, 1);
        $conn = socket_accept($svr_sock);
        socket_write($conn, "Swoole: hello world\n");
        socket_close($conn);
        socket_close($svr_sock);
        $thread->join();
    } else {
        var_dump('child thread 1');
        $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        socket_connect($sock, '127.0.0.1', $tm->getFreePort());
        socket_send($sock, "hello world", 0, 0);
        socket_recv($sock, $buf, 1024, 0);
        Assert::eq($buf, "Swoole: hello world\n");
        socket_close($sock);
    }
    exit(0);
};

$tm->run();
echo "Done\n";
?>
--EXPECT--
string(11) "main thread"
string(14) "child thread 0"
string(14) "child thread 1"
Done
