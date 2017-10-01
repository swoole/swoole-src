--TEST--
swoole_server:
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
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
