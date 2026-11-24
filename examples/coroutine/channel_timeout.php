<?php
// Channel::pop() accepts a timeout so a consumer never waits forever.
// Run: php examples/coroutine/channel_timeout.php
use Swoole\Coroutine\Channel;
use function Swoole\Coroutine\run;

run(function () {
    $chan = new Channel(1);
    var_dump($chan->pop(0.1));   // false: nothing was pushed in time
});
