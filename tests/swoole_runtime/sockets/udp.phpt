--TEST--
swoole_runtime/sockets: udp
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
const GREETINGS = 'hello world';

$GLOBALS['port'] = get_one_free_port();

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

run(function () {
    go(function () {
        $sock = socket_create(AF_INET, SOCK_DGRAM, 0);
        socket_bind($sock, '127.0.0.1', $GLOBALS['port']);

        $n = N;
        while ($n--) {
            $len = socket_recvfrom($sock, $data, 1024, 0, $addr, $port);
            Assert::eq($data, GREETINGS." from $addr:$port");
            $resp = "Swoole: $data";
            socket_sendto($sock, $resp, strlen($resp), 0, $addr, $port);
        }
    });

    $n = N;
    while ($n--) {
        go(function () {
            $sock = socket_create(AF_INET, SOCK_DGRAM, 0);
            socket_connect($sock, '127.0.0.1', $GLOBALS['port']);
            socket_getsockname($sock, $addr, $port);
            $pkt = GREETINGS." from $addr:$port";
            socket_sendto($sock, $pkt, strlen($pkt), 0, '127.0.0.1', $GLOBALS['port']);
            socket_recv($sock, $buf, 1024, 0);
            Assert::eq($buf, "Swoole: $pkt");
            socket_close($sock);
        });
    }
});
echo "Done\n";
?>
--EXPECT--
Done
