<?php


go(function() {

    $db = new Co\MySQL();
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
    $stmt1 = $db->prepare('show tables');
    echo "execute\n";
    $ret1 = $stmt1->execute([]);
    var_dump($ret1);

});

