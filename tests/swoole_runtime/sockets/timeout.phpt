--TEST--
swoole_runtime/sockets: timeout
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
$GLOBALS['port'] = get_one_free_port();

run(function () {
    go(function () {
        $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        socket_bind($sock, '127.0.0.1', $GLOBALS['port']);
        socket_listen($sock, 128);

        $cli = socket_accept($sock);
        $data = socket_read($cli, 1024);
        usleep(60 * 1000);
        socket_write($cli, "Swoole: $data");
        socket_close($cli);
    });


    go(function () {
        $s = microtime(true);
        $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        socket_connect($sock, '127.0.0.1', $GLOBALS['port']);
        socket_send($sock, "hello world", 0, 0);

        $timeout = array(
            "sec"=> 0,
            "usec"=> 50000,
        );
        socket_set_option($sock, SOL_SOCKET, SO_RCVTIMEO, $timeout);
        Assert::eq(socket_get_option($sock, SOL_SOCKET, SO_RCVTIMEO), $timeout);
        Assert::eq(socket_recv($sock, $buf, 1024, 0), false);
        Assert::eq(socket_last_error($sock), SOCKET_ETIMEDOUT);
        $n = socket_recv($sock, $buf, 1024, 0);
        Assert::greaterThanEq($n, 10);
        Assert::eq(strlen($buf), $n);
        Assert::eq($buf, 'Swoole: hello world');
        socket_close($sock);
    });
});
echo "Done\n";
?>
--EXPECT--
Done
