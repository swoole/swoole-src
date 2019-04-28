--TEST--
swoole_channel_coro: unset user class's parent internal property
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
unset($c->capacity);
?>
--EXPECTF--
Fatal error: Uncaught Error: Property capacity of class Swoole\Coroutine\Channel cannot be unset in %s/tests/%s/unset%s.php:%d
Stack trace:
#0 {main}
  thrown in %s