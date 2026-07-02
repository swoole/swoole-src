--TEST--
swoole_windows: iocp socket
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
if (!class_exists(Swoole\Coroutine\Socket::class, false)) {
    die('skip coroutine socket not available');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\run;

$pm = new SwooleTest\ProcessManager();
$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        $sock = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        Assert::assert($sock->connect('127.0.0.1', $pm->getFreePort()));
        Assert::assert($sock->send('ping'));
        Assert::same($sock->recv(4, 1.0), 'pong');
        $sock->close();
    });
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $port = $pm->getFreePort();
    $server = stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr);
    Assert::assert($server !== false, $errstr ?: 'failed to create socket server');
    $pm->wakeup();

    $conn = stream_socket_accept($server, 10);
    Assert::assert($conn !== false, 'failed to accept socket');
    $data = fread($conn, 4);
    Assert::same('ping', $data);
    fwrite($conn, 'pong');
    fclose($conn);
    fclose($server);
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
