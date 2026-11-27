--TEST--
swoole_client_async: datagram client without onClose can be closed and reconnected
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
error_reporting(E_ALL & ~E_DEPRECATED);

$cli = new Swoole\Async\Client(SWOOLE_SOCK_UDP);
$cli->on('receive', function () {});
Assert::true($cli->connect('127.0.0.1', 9));
Assert::true($cli->isConnected());
Assert::true($cli->close());
Assert::false($cli->isConnected());
Assert::eq($cli->sock, -1);

// The connection reference is released, so the object is not kept alive and can connect again.
Assert::true($cli->connect('127.0.0.1', 9));
Assert::true($cli->close());
$ref = WeakReference::create($cli);
unset($cli);
Assert::null($ref->get());
echo "DONE\n";
?>
--EXPECT--
DONE
