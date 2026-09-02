--TEST--
swoole_server_port: set returns whether the settings were applied
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$server = new Server('127.0.0.1', 0, SWOOLE_BASE);
$port = $server->ports[0];

Assert::same((new ReflectionMethod($port, 'set'))->getReturnType()->getName(), 'bool');
Assert::true($port->set(['backlog' => 128]));
Assert::true($server->set(['worker_num' => 1]));

echo "DONE\n";
?>
--EXPECT--
DONE
