<?php

go(function(){
    $swoole_mysql = new \Swoole\Coroutine\MySQL();
    
    $swoole_mysql->connect([
        'host' => '127.0.0.1',
        'port' => 3306,
        'user' => 'root',
        'password' => 'root',
        'database' => 'test',
    ]);
    $res = $swoole_mysql->escape("");
    var_dump($res);
});
    
