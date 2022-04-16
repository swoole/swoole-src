--TEST--
swoole_socket_coro: import 1
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co\run(function () {
    $s = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);

    $s0 = reset($s);
    $s1 = next($s);

    $sock = Swoole\Coroutine\Socket::import($s0);
    Assert::notEmpty($sock);
    $sock->send("test message");
    $sock->close();

    var_dump(stream_get_contents($s1));
});
?>
--EXPECTF--
string(12) "test message"
