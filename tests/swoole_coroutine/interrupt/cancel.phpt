--TEST--
swoole_coroutine: cancel coroutine
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$yield = go(function () {
    if (Co::yield()) {
        echo "resume back\n";
    } else {
        assert(Co::isCancelled());
        echo "yield operation was canceled\n";
    }
});

$sleep = go(function () {
    if (($ret = Co::sleep(1)) === true) {
        echo "normal termination\n";
    } elseif (Co::isCancelled()) {
        assert(is_double($ret));
        assert(time_approximate(1, $ret));
        echo "timer was canceled\n";
    } else {
        echo "create timer error\n";
    }
});

$dns_lookup = go(function () {
    if (Co::gethostbyname('www.swoole.com')) {
        echo "dns loopup ok\n";
    } elseif (Co::isCancelled()) {
        echo "dns lookup was canceled\n";
    } else {
        echo "dns lookup failed\n";
    }
});

$socket_io = go(function () {
    $socket = new  Co\Socket(AF_INET, SOCK_DGRAM, 0);
    if ($socket->recvfrom($peer, 1)) {
        echo "recv from ok\n";
    } elseif (Co::isCancelled()) {
        echo "socket io was canceled\n";
    } else {
        echo "recv from failed\n";
    }
});

$file_io = go(function () {
    if (file_get_contents(__FILE__) === Co::readFile(__FILE__)) {
        echo "read file ok\n";
    } elseif (Co::isCancelled()) {
        echo "file io was canceled\n";
    } else {
        echo "read file failed\n";
    }
});

echo 'cancel yield ' . (Co::cancel($yield) ? 'ok' : 'failed') . "\n";
echo 'cancel sleep ' . (Co::cancel($sleep) ? 'ok' : 'failed') . "\n";
echo 'cancel dns lookup ' . (Co::cancel($dns_lookup) ? 'ok' : 'failed') . "\n";
echo 'cancel socket io ' . (Co::cancel($socket_io) ? 'ok' : 'failed') . "\n";
echo 'cancel file io ' . (Co::cancel($file_io) ? 'ok' : 'failed') . "\n";

?>
--EXPECT--
yield operation was canceled
cancel yield ok
timer was canceled
cancel sleep ok
dns lookup was canceled
cancel dns lookup ok
socket io was canceled
cancel socket io ok
file io was canceled
cancel file io ok
