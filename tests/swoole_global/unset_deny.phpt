--TEST--
swoole_global: deny unset properties and clone
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$chan = new Chan;
$chan->test = 1;
Assert::same($chan->test, 1);
unset($chan->test);
Assert::true(!isset($chan->test));

// clone error
try {
    $chan = clone $chan;
} catch (Error $e) {
    echo "{$e->getMessage()}\n";
}

// unset error
try {
    unset($chan->errCode);
} catch (Error $e) {
    echo "{$e->getMessage()}\n";
    Assert::true(isset($chan->errCode));
}
?>
--EXPECT--
Trying to clone an uncloneable object of class Swoole\Coroutine\Channel
Property errCode of class Swoole\Coroutine\Channel cannot be unset
