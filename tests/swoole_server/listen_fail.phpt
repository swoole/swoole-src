--TEST--
swoole_server: listen fail
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co::set(['log_level' => SWOOLE_LOG_NONE]);
try {
    $serv = new Swoole\Server('192.0.0.1', 80);
} catch (Swoole\Exception $e) {
    Assert::same($e->getCode(), SOCKET_EADDRNOTAVAIL);
    echo "DONE\n";
}
?>
--EXPECT--
DONE
