<?php
use Swoole\Coroutine as co;

co::create(function() {

    $db = new co\MySQL();
    $server = array(
        'host' => '127.0.0.1',
        'user' => 'root',
        'password' => 'root',
        'database' => 'test',
    );

    echo "connect\n";
    $ret1 = $db->connect($server);
    var_dump($ret1);

    echo "prepare [1]\n";
    $stmt1 = $db->prepare('SELECT * FROM userinfo WHERE id=?');
    var_dump($stmt1);
    if ($stmt1 == false)
    {
        var_dump($db->errno, $db->error);
    }

    echo "execute\n";
    $ret3 = $stmt1->execute(array(10));
    var_dump(count($ret3));

    echo "prepare [2]\n";
    $stmt2 = $db->prepare('SELECT * FROM userinfo WHERE id > ? and level > ?');
    var_dump($stmt2);
    if ($stmt2 == false)
    {
        var_dump($db->errno, $db->error);
    }

    echo "execute\n";
    $ret4 = $stmt2->execute(array(10, 99));
    var_dump($ret4);
});

