--TEST--
swoole_server_port: callback cycles release their closures and captured objects
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::setThrowException(true);
$server = new Swoole\Server('127.0.0.1', 0, SWOOLE_BASE);
$port = $server->ports[0];
$callback = function () use ($server, $port) { return 0; };
$weakServer = WeakReference::create($server);
$weakCallback = WeakReference::create($callback);
Assert::true($port->set(['package_length_func' => $callback]));
Assert::true($port->on('receive', $callback));
Assert::true($server->on('workerStart', $callback));
unset($callback, $port, $server);
gc_collect_cycles();
Assert::null($weakServer->get());
Assert::null($weakCallback->get());
echo "DONE\n";
?>
--EXPECT--
DONE
