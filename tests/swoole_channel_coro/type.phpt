--TEST--
swoole_channel_coro: type test
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$exit_status_list = [
    null,
    1,
    1.1,
    'exit',
    ['exit' => 'ok'],
    (object)['exit' => 'ok'],
    STDIN
];


$chan = new Swoole\Coroutine\Channel;

go(function () use ($chan, $exit_status_list)
{
    foreach ($exit_status_list as $val)
    {
        Assert::assert($chan->push($val));
    }
});

go(function () use ($chan, $exit_status_list)
{
    foreach ($exit_status_list as $_val)
    {
        $val = $chan->pop();
        Assert::same($val, $_val);
    }
});


swoole_event_wait();

?>
--EXPECTF--
