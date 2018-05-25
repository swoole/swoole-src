--TEST--
swoole_coroutine: product first without select mode
--SKIPIF--
<?php require  __DIR__ . "/../../include/skipif.inc"; ?>
--FILE--
<?php
$c1 = new chan(2);
//product first without select mode
$num = 10;
go(function () use ($c1,$num) {
    echo "push start\n";
    for ($i=0;$i<$num;$i++)
    {
        $ret = $c1->push("data-$i");
        echo "push [#$i] ret:".var_export($ret,1)."\n";
    }
});

go(function () use ($c1, $num) {
    echo "pop start\n";
    for ($i=0;$i<$num;$i++)
    {
        $ret = $c1->pop();
        echo "pop [#$i] ret:".var_export($ret,1)."\n";
    }
});
echo "main end\n";        
?>
--EXPECT--
push start
push [#0] ret:true
push [#1] ret:true
pop start
pop [#0] ret:'data-0'
pop [#1] ret:'data-1'
main end
push [#2] ret:true
push [#3] ret:true
push [#4] ret:true
pop [#2] ret:'data-2'
pop [#3] ret:'data-3'
pop [#4] ret:'data-4'
push [#5] ret:true
push [#6] ret:true
push [#7] ret:true
pop [#5] ret:'data-5'
pop [#6] ret:'data-6'
pop [#7] ret:'data-7'
push [#8] ret:true
push [#9] ret:true
pop [#8] ret:'data-8'
pop [#9] ret:'data-9'

