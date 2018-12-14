<?php
//chan1 block and chan buffer
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

go(function () use ($c1,$c2,$num) {
    $ori_list = $read_list = [$c1,$c2];
    $write_list = null;
    $result = chan::select($read_list, $write_list, 2);
    echo "select resume res: ".var_export($result,1)."\n";

    if ($ori_list)
    {
        foreach ($ori_list as $chan => $ch)
        {
            for ($i=0;$i<$num;$i++)
            {
                $ret = $ch->pop();
                $chan_id = $chan + 1;
                echo "chan{$chan_id} pop [#$i] ret:".var_export($ret,1)."\n";
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
echo "main end\n";
