--TEST--
swoole_coroutine_channel: channel by return value
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
go(function () {
    $foo = foo();
    $ret = $foo->pop(0.001);
    assert($ret === false);
});
function foo()
{
    $chan = new \Swoole\Coroutine\Channel();
    go(function () use ($chan) {
        // nothing
    });
    return $chan;
}

?>
--EXPECT--