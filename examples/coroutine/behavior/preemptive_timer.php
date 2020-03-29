<?php
co::set(['enable_preemptive_scheduler' => true]);
go(function (){
    $exit = false;
    while (true){
        $res = Swoole\Coroutine::stats();
        $num = $res['coroutine_num'];
        if ($num < 10){
            go(function () use(&$exit){
                echo "cid:".Swoole\Coroutine::getCid()." start\n";
                Swoole\Coroutine::sleep(1);
                echo "cid ".Swoole\Coroutine::getCid()." end\n";
                $exit = true;
            });
        }
        if ($exit) {
            echo "cid ".Swoole\Coroutine::getCid()." break\n";
            break;
        }
    }
    echo "cid ".Swoole\Coroutine::getCid()." exit\n";
});
echo "main end\n";

