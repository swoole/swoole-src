--TEST--
swoole_coroutine: shutdown coroutine
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$yield = go(function () {
    Co::yield();
    echo "never here (yield)\n";
});

$sleep = go(function () {
    Co::sleep(1);
    echo "never here (sleep)\n";
});

$chan = go(function () {
    $chan = new Chan();
    while ($ret = $chan->pop()) {
        var_dump($ret);
    }
    echo "never here (chan)\n";
});

$dns_lookup = go(function () {
    Co::gethostbyname('www.swoole.com');
    echo "never here (dns lookup)\n";
});

$socket_io = go(function () {
    $socket = new  Co\Socket(AF_INET, SOCK_DGRAM, 0);
    $socket->recvfrom($peer, 1);
    echo "never here (socket io)\n";
});

$file_io = go(function () {
    Co::readFile(__FILE__);
    echo "never here (file io)\n";
});

echo 'shutdown yield ' . (Co::shutdown($yield) ? 'ok' : 'failed') . "\n";
echo 'shutdown sleep ' . (Co::shutdown($sleep) ? 'ok' : 'failed') . "\n";
echo 'shutdown chan ' . (Co::shutdown($chan) ? 'ok' : 'failed') . "\n";
echo 'shutdown dns lookup ' . (Co::shutdown($dns_lookup) ? 'ok' : 'failed') . "\n";
echo 'shutdown socket io ' . (Co::shutdown($socket_io) ? 'ok' : 'failed') . "\n";
echo 'shutdown file io ' . (Co::shutdown($file_io) ? 'ok' : 'failed') . "\n";

?>
--EXPECT--
shutdown yield ok
shutdown sleep ok
shutdown chan ok
shutdown dns lookup ok
shutdown socket io ok
shutdown file io ok
