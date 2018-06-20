--TEST--
swoole_coroutine: product first with select mode
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

$c1 = new chan(1);
//product first with select mode
$num = 10;
go(function () use ($c1,$num) {
    echo "push start\n";
    for ($i=0;$i<$num;$i++)
    {
        $ret = $c1->push("data-$i");
        echo "push [#$i] ret:".var_export($ret,1)."\n";
    }
});

go(function () use ($c1,$num) {
    $read_list = [$c1];
    $write_list = null;
    echo "select yield\n";
    $result = chan::select($read_list, $write_list, 2);
    echo "select resume res: ".var_export($result,1)."\n";
    if ($read_list)
    {
        foreach($read_list as $ch)
        {
            for ($i=0;$i<$num;$i++)
            {
                $ret = $ch->pop();
                echo "pop [#$i] ret:".var_export($ret,1)."\n";
            }
        }
    }
});
echo "main end\n";
?>
--EXPECT--
push start
push [#0] ret:true
select yield
select resume res: true
pop [#0] ret:'data-0'
main end
push [#1] ret:true
push [#2] ret:true
pop [#1] ret:'data-1'
pop [#2] ret:'data-2'
push [#3] ret:true
push [#4] ret:true
pop [#3] ret:'data-3'
pop [#4] ret:'data-4'
push [#5] ret:true
push [#6] ret:true
pop [#5] ret:'data-5'
pop [#6] ret:'data-6'
push [#7] ret:true
push [#8] ret:true
pop [#7] ret:'data-7'
pop [#8] ret:'data-8'
push [#9] ret:true
pop [#9] ret:'data-9'
