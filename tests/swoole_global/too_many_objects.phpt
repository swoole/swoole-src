--TEST--
swoole_global: too many objects
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$object_store = [];
for ($n = 65536; $n--;) {
    $object_store[] = new stdClass();
}
$server = new swoole_websocket_server('127.0.0.1', get_one_free_port(), SWOOLE_BASE);
$tcp_server = $server->listen('127.0.0.1', get_one_free_port(), SWOOLE_TCP);
echo "DONE\n";
?>
--EXPECT--
DONE
