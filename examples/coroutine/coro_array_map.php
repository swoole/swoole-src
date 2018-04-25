<?php

use Swoole\Coroutine as co;

co::create(function() {
    array_map("test",array("func param\n"));
    echo "co flow end\n";
});

function test($p) {
    go(function() use ($p){
        echo $p;
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $res = $client->connect('127.0.0.1', 9501, 1);
        echo "co resume : connect ret = ".var_export($res,1)."\n";
        echo "map func end \n";
    });
}
echo "main end\n";
