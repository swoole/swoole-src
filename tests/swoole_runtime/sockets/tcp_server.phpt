--TEST--
swoole_runtime/sockets: tcp server
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

const N = 8;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

$GLOBALS['port'] = get_one_free_port();
$GLOBALS['time'] = [];
$s = microtime(true);
run(function () {
    go(function () {
        $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        socket_bind($sock, '127.0.0.1', $GLOBALS['port']);
        socket_listen($sock, 128);

        $n = N;
        while ($n--) {
            $cli = socket_accept($sock);
            go(function () use ($cli) {
                $data = socket_read($cli, 1024);
                usleep(30 * 1000);
                socket_write($cli, "Swoole: $data");
                socket_close($cli);
            });
        }
    });

    $n = N;
    while ($n--) {
        go(function () {
            $s = microtime(true);
            $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
            socket_connect($sock, '127.0.0.1', $GLOBALS['port']);
            socket_send($sock, "hello world", 0, 0);
            socket_recv($sock, $buf, 1024, 0);
            Assert::greaterThanEq(strlen($buf), 15);
            Assert::eq($buf, 'Swoole: hello world');
            socket_close($sock);
            $GLOBALS['time'][] = microtime(true) - $s;
        });
    }
});
echo "Done\n";
Assert::lessThanEq(microtime(true) - $s, array_sum($GLOBALS['time']) / 3);
?>
--EXPECT--
Done
