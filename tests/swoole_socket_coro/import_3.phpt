--TEST--
swoole_socket_coro: import 3
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
if (!extension_loaded('sockets')) {
    die('SKIP sockets extension not available.');
}
$s = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
$br = @socket_bind($s, '0.0.0.0', 58379);
if ($br === false)
    die("SKIP IPv4/port 58379 not available");
$so = @socket_set_option($s, IPPROTO_IP, MCAST_JOIN_GROUP, array(
    "group" => '224.0.0.23',
    "interface" => "lo",
));
if ($so === false) {
    die("SKIP joining group 224.0.0.23 on interface lo failed");
}
socket_close($s);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co\run(function () {
    $stream = stream_socket_server("udp://0.0.0.0:58379", $errno, $errstr, STREAM_SERVER_BIND);
    $sock = Swoole\Coroutine\Socket::import($stream);
    Assert::isInstanceOf($sock, Swoole\Coroutine\Socket::class);
    $so = $sock->setOption(IPPROTO_IP, MCAST_JOIN_GROUP, array(
        "group" => '224.0.0.23',
        "interface" => "lo",
    ));
    var_dump($so);

    $sendsock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    Assert::isInstanceOf($sock, Swoole\Coroutine\Socket::class);

    $br = socket_bind($sendsock, '127.0.0.1');
    $so = socket_sendto($sendsock, $m = "my message", strlen($m), 0, "224.0.0.23", 58379);
    var_dump($so);

    stream_set_blocking($stream, 0);
    var_dump(fread($stream, strlen($m)));
    echo "Done.\n";
});
?>
--EXPECTF--
bool(true)
int(10)
string(10) "my message"
Done.
