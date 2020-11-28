--TEST--
swoole_runtime/sockets: tcp client
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

$GLOBALS['time'] = [];
$s = microtime(true);
run(function () {
    $n = N;
    while($n--) {
        go(function() {
            $s = microtime(true);
            $domain = 'www.baidu.com';
            $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
            socket_connect($sock, $domain, 80);
            socket_write($sock, "GET / HTTP/1.0\r\nHost: $domain\r\nConnection: close\r\nKeep-Alive: off\r\n\r\n");

            $html = '';
            while(true) {
                $data = socket_read($sock, 8192);
                if ($data == '') {
                    break;
                }
                $html .= $data;
            }

            Assert::greaterThanEq(strlen($html), 10000);
            Assert::contains($html, 'baidu.com');
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
