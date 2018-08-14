<?php
go(function () {
    Swoole\Runtime::enableCoroutine();

    $redis = new redis;
    $retval = $redis->connect("127.0.0.1", 6379);
    var_dump($retval, $redis->getLastError());
    var_dump($redis->get("key"));
    var_dump($redis->set("key", "value2"));
    var_dump($redis->get("key"));
    $redis->close();


    $db = new mysqli;
    $db->connect('127.0.0.1', 'root', 'root', 'test');

    $result = $db->query("show databases");
    var_dump($result->fetch_all());

    $db = new PDO("mysql:host=127.0.0.1;dbname=test;charset=utf8", "root" ,"root");
    $query = $db->prepare("select * from userinfo where id=?");
    $rs = $query->execute(array(1));
    var_dump($rs);
    echo count($query->fetchAll());
});
