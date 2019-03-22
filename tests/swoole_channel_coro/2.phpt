--TEST--
swoole_channel_coro: consumer first without select mode
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$c1 = new chan();
//consumer first without select mode
$num = 10;
go(function () use ($c1, $num) {
    echo "pop start\n";
    for ($i=0;$i<$num;$i++)
    {
        $ret = $c1->pop();
        echo "pop [#$i] ret:".var_export($ret,1)."\n";
    }
});

go(function () use ($c1,$num) {
    echo "push start\n";
    for ($i=0;$i<$num;$i++)
    {
        $ret = $c1->push("data-$i");
        echo "push [#$i] ret:".var_export($ret,1)."\n";
    }

});
echo "main end\n";
swoole_event_wait();
?>
--EXPECT--
pop start
push start
pop [#0] ret:'data-0'
push [#0] ret:true
pop [#1] ret:'data-1'
push [#1] ret:true
pop [#2] ret:'data-2'
push [#2] ret:true
pop [#3] ret:'data-3'
push [#3] ret:true
pop [#4] ret:'data-4'
push [#4] ret:true
pop [#5] ret:'data-5'
push [#5] ret:true
pop [#6] ret:'data-6'
push [#6] ret:true
pop [#7] ret:'data-7'
push [#7] ret:true
pop [#8] ret:'data-8'
push [#8] ret:true
pop [#9] ret:'data-9'
push [#9] ret:true
main end
