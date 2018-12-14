<?php

go(function(){
    $db = new Swoole\Coroutine\Mysql;
    $server = [
        'host'     => 'unix:/tmp/mysql.sock',
        'user'     => 'root',
        'password' => 'root',
        'database' => 'test'
    ];
    $db->connect($server);
    $stmt = $db->prepare('SELECT * FROM `user` WHERE id=?');
    $ret = $stmt->execute([1]);
    var_dump($ret);
});
