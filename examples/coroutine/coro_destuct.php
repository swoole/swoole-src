<?php
require __DIR__ . "/coro_include.php";

class T
{
    function __construct()
    {
        echo "call __construct \n";
    }

      function test()
      {
        echo "call function \n";
      }

      function __destruct()
      {
        echo "call __destruct \n";
        go(function () {
            echo "co[1] start\n";
            $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
            $res = $client->connect('127.0.0.1', 9501, 1);
            co::sleep(1.0);
            echo "co[1] resume : connect ret = ".var_export($res,1)."\n";
            echo "co[1] exit\n";
        });
      }
}

$t = new T();
$t->test();
unset($t);
