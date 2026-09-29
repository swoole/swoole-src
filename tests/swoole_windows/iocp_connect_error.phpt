--TEST--
swoole_windows: IOCP normalizes refused connection errors
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

use Swoole\Coroutine\Socket;

use function Swoole\Coroutine\run;

$port = get_one_free_port();

run(function () use ($port) {
    $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::false($socket->connect('127.0.0.1', $port));
    Assert::contains(strtolower($socket->errMsg), 'refused');
});

echo "DONE\n";
?>
--EXPECT--
DONE
