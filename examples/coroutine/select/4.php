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
