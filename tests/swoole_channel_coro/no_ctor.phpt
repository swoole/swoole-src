--TEST--
swoole_channel_coro: no ctor
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

class MyChan extends Swoole\Coroutine\Channel {
    function __construct($size = null) {

    }
}

go(function () {
   $chan = new MyChan(100);
    $chan->pop();
});

?>
--EXPECTF--
Fatal error: Swoole\Coroutine\Channel::pop(): you must call Channel constructor first in %s on line %d
