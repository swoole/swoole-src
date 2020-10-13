--TEST--
swoole_server: listen fail
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
//调高log_level
Co::set(['log_level' => SWOOLE_LOG_NONE]);
try {
    $serv = new swoole_server('192.0.0.1', 80);
} catch (swoole_exception $e) {
    Assert::same($e->getCode(), SOCKET_EADDRNOTAVAIL);
    echo "DONE\n";
}
?>
--EXPECT--
DONE
