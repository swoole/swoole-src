<?php
//chan1 block and chan buffer
$c1 = new chan(0);
go(function () use ($c1) {
    $num = 10;
    for ($i=0;$i<$num;$i++)
    {
        $ret = $c1->push("chan1-$i");
        echo "chan push [#$i] ret:".var_export($ret,1)."\n";
    }
});

go(function () use ($c1) {
    $ret = $c1->pop();
    echo "chan pop ret:".var_export($ret,1)."\n";
    co::sleep(1);
    $ret = $c1->pop();
    echo "chan pop ret:".var_export($ret,1)."\n";
});
