--TEST--
swoole_channel_coro: discard
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Scheduler;
use Swoole\Coroutine\Channel;

$scheduler = new Scheduler();
$scheduler->add(function () {
    $chan = new Channel(1);
    $chan->push(1, -1);
    var_dump('push success');
    $chan->push(1, -1);
});
$scheduler->start();
var_dump('scheduler end');

?>
--EXPECTF--
string(12) "push success"
string(13) "scheduler end"
[%s]	WARNING	Channel::~Channel() (ERRNO 10003): channel is destroyed, 1 producers will be discarded
