--TEST--
swoole_global: unset user class's own property
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
class C extends chan
{
    public $t = 1;
}
$c = new C;
unset($c->t);
?>
--EXPECTF--
