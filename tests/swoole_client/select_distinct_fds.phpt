--TEST--
swoole_client: select() with different sockets in each array does not overflow
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

[$a1, $a2] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
[$b1, $b2] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
[$c1, $c2] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);

for ($i = 0; $i < 200; $i++) {
    $r = [$a1, $a1, $a1];
    $w = [$b1, $c1, $a2];
    $e = [$b2, $c2, $a2, $a1];
    $n = swoole_client_select($r, $w, $e, 0.1);
    if ($n < 1) {
        echo "FAIL\n";
        break;
    }
}
fwrite($a2, 'x');
$r = [$a1];
$w = [];
$e = [];
var_dump(swoole_client_select($r, $w, $e, 1) >= 1, count($r));
echo "DONE\n";
?>
--EXPECT--
bool(true)
int(1)
DONE
