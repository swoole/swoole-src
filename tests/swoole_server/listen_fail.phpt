--TEST--
swoole_server:
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
//调高log_level
Swoole\Async::set(['log_level' => 8]);
try
{
    $serv = new swoole_server('192.0.0.1', 80);
}
catch(swoole_exception $e)
{
    assert($e->getCode() == 99);
}
?>
--EXPECT--
