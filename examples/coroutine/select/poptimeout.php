<?php
//chan1 block and chan buffer
$c1 = new chan(1);


go(function () use ($c1) {
    $start = microtime(1);
    $ret = $c1->pop(1);
    $end = microtime(1);
    echo "chan pop ret:".var_export($ret,1)." error:".$c1->errCode."\n";
    echo "use time:".($end-$start)."s\n";

});

go(function () use ($c1) {
    co::sleep(2);
    echo "sleep 2\n";
    $ret = $c1->push("chan-1");
    echo "chan push ret:".var_export($ret,1)." error:".$c1->errCode."\n";
});
