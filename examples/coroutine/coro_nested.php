<?php
require __DIR__ . "/coro_include.php";
function test()
{
    echo "before coro\n";
    go(function () {
        echo "co[1] start\n";
        go(function () {
            echo "co[2] start\n";
              go(function () {
                  echo "co[3] start\n";
                  $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
                  $res = $client->connect('127.0.0.1', 9501, 1);
                  co::sleep(3.0);
                  echo "co[3] resume : connect ret = ".var_export($res,1)."\n";
                  echo "co[3] exit\n";
              });
            echo "co[2] restart\n";
            $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
            $res = $client->connect('127.0.0.1', 9501, 1);
            co::sleep(2.0);
            echo "co[2] resume : connect ret = ".var_export($res,1)."\n";
            echo "co[2] exit\n";
        });
        echo "co[1] restart\n";
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $res = $client->connect('127.0.0.1', 9501, 1);
        // co::sleep(1.0);
        var_dump($res);
        echo "co[1] resume : connect ret = ".var_export($res,1)."\n";
        echo "co[1] exit\n";
    });
    echo "out coro \n";
}
test();
// swoole_event_wait();
