--TEST--
swoole_socket_coro: readVector all
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

use Swoole\Coroutine\Socket;

use function Swoole\Coroutine\run;

require __DIR__ . '/../include/bootstrap.php';

$totalLength = 0;
$iovector = [];
$packedStr = '';

for ($i = 0; $i < 10; $i++) {
    $iovector[$i] = str_repeat(get_safe_random(1024), 128);
    $totalLength += strlen($iovector[$i]);
    $packedStr .= $iovector[$i];
}

run(function () {
    $server = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    $port = get_one_free_port();

    go(function () use ($server, $port) {
        Assert::assert($server->bind('127.0.0.1', $port));
        Assert::assert($server->listen(512));
        $conn = $server->accept();
        Assert::assert($conn instanceof  Socket);
        Assert::assert($conn->fd > 0);

        global $iovector;
        Assert::assert($conn instanceof Socket);
        $iov = [];
        for ($i = 0; $i < 10; $i++) {
            $iov[] = 1024 * 128;
        }
        Assert::eq($conn->readVectorAll($iov), $iovector);
    });

    go(function () use ($server, $port) {
        global $packedStr, $totalLength;

        $conn = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        Assert::assert($conn->connect('127.0.0.1', $port));
        $ret = $conn->sendAll($packedStr);
        Assert::eq($ret, $totalLength);
        $server->close();
    });
});

echo "DONE\n";
?>
--EXPECT--
DONE
