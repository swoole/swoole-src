<?php
echo "start\n";
go(function () {
    echo "coro start\n";
    $arr = range(0, 20);
    foreach($arr as $k=>$v){
        echo $v."\n";
    }
});

go(function () {
    echo "222222\n";
});
echo "end\n";
