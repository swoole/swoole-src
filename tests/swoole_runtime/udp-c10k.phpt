--TEST--
swoole_runtime: server and client concurrency
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

// udp server & client with 12.8k requests in single process
$port = get_one_free_port();

go(function () use ($port) {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
    $socket->bind('127.0.0.1', $port);
    $client_map = [];
    for ($c = MAX_CONCURRENCY_MID; $c--;) {
        for ($n = 0; $n < MAX_REQUESTS; $n++) {
            $recv = $socket->recvfrom($peer);
            $client_uid = "{$peer['address']}:{$peer['port']}";
            $id = $client_map[$client_uid] = ($client_map[$client_uid] ?? -1) + 1;
            Assert::same($recv, "Client: Hello #{$id}!");
            $socket->sendto($peer['address'], $peer['port'], "Server: Hello #{$id}!");
        }
    }
    $socket->close();
    echo "DONE\n";
});
for ($c = MAX_CONCURRENCY_MID; $c--;) {
    go(function () use ($port) {
        $fp = stream_socket_client("udp://127.0.0.1:{$port}", $errno, $errstr, 1);
        if (!$fp) {
            echo "$errstr ($errno)\n";
        } else {
            for ($n = 0; $n < MAX_REQUESTS; $n++) {
                fwrite($fp, "Client: Hello #{$n}!");
                $recv = fread($fp, 1024);
                list($_address, $_port) = explode(':', (stream_socket_get_name($fp, true)));
                Assert::assert($_address === '127.0.0.1' && (int)$_port === $port);
                Assert::same($recv, "Server: Hello #{$n}!");
            }
            fclose($fp);
        }
    });
}

?>
--EXPECT--
DONE
