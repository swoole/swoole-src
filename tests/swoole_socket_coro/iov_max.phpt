--TEST--
swoole_socket_coro: iov max
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

use Swoole\Coroutine\Socket;

use function Swoole\Coroutine\run;

require __DIR__ . '/../include/bootstrap.php';

run(function () {
    $iovector = [];
    $iovectorLength = [];

    for ($i = 0; $i < SWOOLE_IOV_MAX + 1; $i++) {
        $iovector[$i] = 'a';
    }

    for ($i = 0; $i < SWOOLE_IOV_MAX + 1; $i++) {
        $iovectorLength[$i] = 1;
    }

    $conn = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::false($conn->writeVectorAll($iovector));
    Assert::eq($conn->errCode, SOCKET_EINVAL);
    Assert::eq($conn->errMsg, "The maximum of iov count is " . SWOOLE_IOV_MAX);

    Assert::false($conn->readVectorAll($iovectorLength));
    Assert::eq($conn->errCode, SOCKET_EINVAL);
    Assert::eq($conn->errMsg, "The maximum of iov count is " . SWOOLE_IOV_MAX);
});

echo "DONE\n";
?>
--EXPECT--
DONE
