<?php
const N = 100000;

function test()
{
    global $timers;
    shuffle($timers);
    $stime = microtime(true);
    foreach($timers as $id)
    {
        swoole_timer_clear($id);
    }
    $etime = microtime(true);
    echo "del ".N." timer :". ($etime - $stime)."s\n";
}

class TestClass
{
    static function timer()
    {

    }
}

$timers = [];
$stime = microtime(true);
for($i = 0; $i < N; $i++)
{
    $timers[] = swoole_timer_after(rand(1, 9999999), 'test');
    //swoole_timer_after(rand(1, 9999999), function () {
    //    echo "hello world\n";
    //});
    //swoole_timer_after(rand(1, 9999999), array('TestClass', 'timer'));
}
$etime = microtime(true);
echo "add ".N." timer :". ($etime - $stime)."s\n";
swoole_event_wait();
