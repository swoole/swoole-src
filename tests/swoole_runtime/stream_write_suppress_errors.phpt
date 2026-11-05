--TEST--
swoole_runtime: stream write errors honor PHP_STREAM_FLAG_SUPPRESS_ERRORS
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('pdo_mysql');
?>
--INI--
error_reporting=E_ALL
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Socket;
use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

function send_packet(Socket $socket, string $payload, int $sequence): void
{
    $socket->sendAll(substr(pack('V', strlen($payload)), 0, 3) . chr($sequence) . $payload);
}

run(function () {
    $server = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($server->bind('127.0.0.1'));
    Assert::true($server->listen());
    $port = $server->getsockname()['port'];
    $connected = new Channel(1);

    go(function () use ($server, $connected) {
        $conn = $server->accept();
        $capabilities = 0x00088201;
        send_packet($conn, "\x0a8.0.0\0" . pack('V', 1) . "12345678\0"
            . pack('v', $capabilities & 0xffff) . "\x21" . pack('v', 2)
            . pack('v', $capabilities >> 16) . "\x15" . str_repeat("\0", 10)
            . "abcdefghijkl\0mysql_native_password\0", 0);
        $header = $conn->recvAll(4);
        $conn->recvAll(unpack('V', substr($header, 0, 3) . "\0")[1]);
        send_packet($conn, "\0\0\0\x02\0\0\0", 2);

        $connected->pop();
        $conn->setOption(SOL_SOCKET, SO_LINGER, ['l_onoff' => 1, 'l_linger' => 0]);
        $conn->close();
    });

    $pdo = new PDO("mysql:host=127.0.0.1;port={$port}", 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $connected->push(true);
    // Coroutine sockets close their descriptor in a deferred callback, so wait for the reset.
    Coroutine::sleep(0.01);

    // mysqlnd sets PHP_STREAM_FLAG_SUPPRESS_ERRORS and reports the failed write itself.
    try {
        $pdo->query('SELECT 1');
    } catch (PDOException $e) {
        echo $e->getMessage(), PHP_EOL;
    }
});
?>
--EXPECT--
SQLSTATE[HY000]: General error: 2006 MySQL server has gone away
