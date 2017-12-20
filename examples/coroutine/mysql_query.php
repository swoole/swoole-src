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

    echo "prepare\n";
    $ret2 = $db->query('SELECT * FROM userinfo WHERE id=3');
    var_dump($ret2);
});

