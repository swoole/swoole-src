--TEST--
swoole_client_sync: udg send timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
const N = 65507;
define("SOCKET_FILE", __DIR__.'/server.sock');
$socket = stream_socket_server("udg://".SOCKET_FILE, $errno, $errstr, STREAM_SERVER_BIND);

$client = new swoole_client(SWOOLE_SOCK_UNIX_DGRAM);
$client->connect(SOCKET_FILE, 0, 0.3);
$s = microtime(true);

while (true) {
    $re = $ret = $client->sendto(SOCKET_FILE, 0, str_repeat('B', N));
    if ($re == false) {
        break;
    }
}
unlink(SOCKET_FILE);
Assert::lessThan(microtime(true) - $s, 0.8);
?>
--EXPECT--
