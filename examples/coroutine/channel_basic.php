<?php
// A Channel passes data between coroutines without locks.
// Run: php examples/coroutine/channel_basic.php
use Swoole\Coroutine\Channel;
use function Swoole\Coroutine\run;

run(function () {
    $chan = new Channel(2);
    Swoole\Coroutine::create(function () use ($chan) {
        $chan->push('hello from the producer');
    });
    echo $chan->pop(), PHP_EOL;
});
