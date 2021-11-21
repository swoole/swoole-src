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

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

const N = 4;

run(function () {
    $pair = [];
    Assert::true(socket_create_pair(AF_UNIX, SOCK_DGRAM, 0, $pair));

    go(function () use ($pair) {
        $n = N;
        while ($n--) {
            $data = "hello co-2, #$n\n";
            socket_write($pair[0], $data);
        }

        $n = N;
        while ($n--) {
            echo socket_read($pair[0], 1024);
        }
    });

    go(function () use ($pair) {
        $n = N;
        while ($n--) {
            $data = "hello co-1, #$n\n";
            socket_write($pair[1], $data);
        }

        $n = N;
        while ($n--) {
            echo socket_read($pair[1], 1024);
        }
    });

});
echo "Done\n";
?>
--EXPECT--
hello co-2, #3
hello co-2, #2
hello co-2, #1
hello co-2, #0
hello co-1, #3
hello co-1, #2
hello co-1, #1
hello co-1, #0
Done
