<?php

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
use Swoole\Coroutine;
use Swoole\Coroutine\System;

//run(function () {
//    $cid_list = [];
//    for ($i = 0; $i < 10; $i++) {
//        $cid_list[] = go(function () use ($i) {
//            System::sleep(.3);
//            echo "hello $i\n";
//        });
//    }
//
//    Coroutine::join($cid_list);
//
//    echo "all done\n";
//});


run(function () {
    $result = [];
    Coroutine::join([
        go(function () use (&$result) {
            $result['baidu'] = file_get_contents("https://www.baidu.com/");
        }),
        go(function () use (&$result) {
            $result['taobao'] = file_get_contents("https://www.taobao.com/");
        })
    ]);

    echo "all done\n";
    var_dump($result);
});
