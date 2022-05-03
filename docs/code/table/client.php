<?php
/**
 * User: lufei
 * Date: 2020/8/13
 * Email: lufei@swoole.com
 */
Co\run(function (){
    go(function(){
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        if (!$client->connect('127.0.0.1', 9501, 0.5))
        {
            echo "connect failed. Error: {$client->errCode}\n";
        }
        $client->send("hello world\n");
        while (1) {
            echo $client->recv();
            \Co::sleep(5);
        }
    });

    go(function(){
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        if (!$client->connect('127.0.0.1', 9501, 0.5))
        {
            echo "connect failed. Error: {$client->errCode}\n";
        }
        $client->send("hello world\n");
        while (1) {
            echo $client->recv();
            \Co::sleep(5);
        }
    });
});