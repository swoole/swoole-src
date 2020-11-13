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

Assert::false($client->connect('127.0.0.1', 9501));
Assert::eq($client->errCode, SOCKET_EADDRINUSE);

echo "DONE\n";
?>
--EXPECTF--
Warning: Swoole\Client::connect(): bind address or port error in set method in %s
DONE
