<?php
go(function () {
    $db = new Swoole\Coroutine\Mysql;
    $server = [
        'host'     => '127.0.0.1',
        'user'     => 'root',
        'password' => 'root',
        'database' => 'test'
    ];
    $db->connect($server);
    $stmt = $db->prepare('SELECT * FROM `userinfo`');
    $ret = $stmt->execute();
    var_dump($ret);
});
