--TEST--
swoole_channel_coro: hybird channel
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
exit("skip for select");
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$c1 = new chan();
$c2 = new chan(10);
$num = 10;
go(function () use ($c2,$num) {
    for ($i=0;$i<$num;$i++)
    {
        $ret = $c2->push("chan2-$i");
        echo "chan 2 push [#$i] ret:".var_export($ret,1)."\n";
    }
});
go(function () use ($c1,$num) {
    $read_list = [$c1];
    $write_list = null;
    $result = chan::select($read_list, $write_list, 2);
    echo "select resume res: ".var_export($result,1)."\n";
    if ($read_list)
    {
        foreach($read_list as $ch)
        {
            for ($i=0;$i<$num;$i++)
            {
                $ret = $ch->pop();
                echo "chan1 pop [#$i] ret:".var_export($ret,1)."\n";
            }
        }
    }
});

go(function () use ($c1,$num) {
    echo "chan1 push start\n";
    for ($i=0;$i<$num;$i++)
    {
        if ($i == 2) {
            echo "start sleep\n";
            co:sleep(1);
            echo "end sleep\n";
        }
        $ret = $c1->push("chan1-$i");
        echo "chan1 push [#$i] ret:".var_export($ret,1)."\n";
    }

});

go(function () use ($c2,$num) {
    echo "chan2 pop start\n";
    for ($i=0;$i<$num;$i++)
    {
        $ret = $c2->pop();
        echo "chan2 pop [#$i] ret:".var_export($ret,1)."\n";
    }
});
echo "main end\n";
?>
--EXPECT--
chan 2 push [#0] ret:true
chan 2 push [#1] ret:true
chan 2 push [#2] ret:true
chan 2 push [#3] ret:true
chan 2 push [#4] ret:true
chan 2 push [#5] ret:true
chan 2 push [#6] ret:true
chan 2 push [#7] ret:true
chan 2 push [#8] ret:true
chan 2 push [#9] ret:true
chan1 push start
chan2 pop start
chan2 pop [#0] ret:'chan2-0'
chan2 pop [#1] ret:'chan2-1'
chan2 pop [#2] ret:'chan2-2'
chan2 pop [#3] ret:'chan2-3'
chan2 pop [#4] ret:'chan2-4'
chan2 pop [#5] ret:'chan2-5'
chan2 pop [#6] ret:'chan2-6'
chan2 pop [#7] ret:'chan2-7'
chan2 pop [#8] ret:'chan2-8'
chan2 pop [#9] ret:'chan2-9'
main end
select resume res: true
chan1 pop [#0] ret:'chan1-0'
chan1 push [#0] ret:true
chan1 pop [#1] ret:'chan1-1'
chan1 push [#1] ret:true
start sleep
end sleep
chan1 pop [#2] ret:'chan1-2'
chan1 push [#2] ret:true
chan1 pop [#3] ret:'chan1-3'
chan1 push [#3] ret:true
chan1 pop [#4] ret:'chan1-4'
chan1 push [#4] ret:true
chan1 pop [#5] ret:'chan1-5'
chan1 push [#5] ret:true
chan1 pop [#6] ret:'chan1-6'
chan1 push [#6] ret:true
chan1 pop [#7] ret:'chan1-7'
chan1 push [#7] ret:true
chan1 pop [#8] ret:'chan1-8'
chan1 push [#8] ret:true
chan1 pop [#9] ret:'chan1-9'
chan1 push [#9] ret:true
