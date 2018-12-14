<?php
use Swoole\Coroutine as co;

$chan = new co\Channel(2);
$n = 10;
for ($i = 0; $i < $n; $i++) {
    go(function () use ($i,$chan) {
        $ret = $chan->push($i);
        echo "push {$i} res:".var_export($ret, 1)."\n";
    });
};
go(function ()use ($chan){
    $bool = true;
    while ($bool){
        $data = $chan->pop();
        echo "pop res:".var_export($data, 1)."\n";
        if($data===false){
            $bool = false;
        }
        //var_dump($data);
    }
});
