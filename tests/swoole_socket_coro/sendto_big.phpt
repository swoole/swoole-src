--TEST--
swoole_socket_coro: sendto
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$randomData = '';
Co\run(function () {
    go(function () {
        $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
        $socket->bind('127.0.0.1', 9601);
        $data = $socket->recvfrom($peer);
        Assert::same($data, 'hello');
        Assert::same($peer['address'], '127.0.0.1');
        Assert::greaterThan($peer['port'], 0);
        global $randomData;
        for ($x = 0; $x < MAX_CONCURRENCY; $x++) {
            for ($y = 0; $y < MAX_CONCURRENCY; $y++) {
                $chunk = get_safe_random(1024);
                $randomData .= $chunk;
                Assert::same($socket->sendto($peer['address'], $peer['port'], $chunk), strlen($chunk));
            }
            Co::sleep(0.001);
        }
        // close
        Assert::same($socket->sendto($peer['address'], $peer['port'], ''), 0);
    });
    go(function () {
        $socket = new  Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
        $socket->sendto('127.0.0.1', 9601, 'hello');
        $data = '';
        while (true) {
            $tmp = $socket->recvfrom($peer);
            if (empty($tmp)) {
                break;
            }
            $data .= $tmp;
        }
        global $randomData;
        if (Assert::same($data, $randomData)) {
            echo "OK\n";
        }
    });
});
?>
--EXPECT--
OK
