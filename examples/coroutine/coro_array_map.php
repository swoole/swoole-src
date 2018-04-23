<?php

use Swoole\Coroutine as co;

co::create(function() {
    array_map("test",array("func param\n"));
    echo "co flow end\n";
});
    
function test($p) {
    echo $p;
    co::sleep(1);
    echo "map func end \n";
}
echo "main end\n";
