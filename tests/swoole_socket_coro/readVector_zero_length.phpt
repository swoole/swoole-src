--TEST--
swoole_socket_coro: readVector rejects zero-length entries
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
use Swoole\Coroutine\Socket;
use function Swoole\Coroutine\run;

run(function () {
    $conn = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    try {
        $conn->readVector([1, 0]);
    } catch (Throwable $e) {
        echo $e->getMessage(), PHP_EOL;
    }
});
?>
--EXPECT--
Item #[1] must be greater than 0
