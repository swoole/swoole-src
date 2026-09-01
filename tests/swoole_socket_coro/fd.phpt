--TEST--
swoole_socket_coro: fd
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$sockets = [];
$requestCount = IS_WIN ? 128 : MAX_REQUESTS;
for ($n = $requestCount; $n--;) {
    $sockets[] = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (!IS_WIN && count($sockets) > 1) {
        Assert::assert(end($sockets)->fd === prev($sockets)->fd + 1);
    } else {
        Assert::greaterThan(end($sockets)->fd, 0);
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
