--TEST--
swoole_client_sync: bind address
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;
use Swoole\Coroutine\Socket;

$socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
$socket->bind('127.0.0.1', 9501);

$client = new Client(SWOOLE_SOCK_TCP);
$client->set([
    'bind_address' => '127.0.0.1',
    'bind_port' => 9501,
]);

try {
    $client->connect('127.0.0.1', 9501);
} catch (\Exception $e) {
    echo get_class($e) . PHP_EOL;
    Assert::eq($e->getCode(), SOCKET_EADDRINUSE);
    Assert::eq($e->getMessage(), swoole_strerror(SOCKET_EADDRINUSE));
}

echo "DONE\n";
?>
--EXPECT--
Swoole\Client\Exception
DONE
