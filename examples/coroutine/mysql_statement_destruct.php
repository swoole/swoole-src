<?php
go(function () {
    $db = new Swoole\Coroutine\Mysql;
    $server = [
        'host' => '127.0.0.1',
        'user' => 'root',
        'password' => 'root',
        'database' => 'test'
    ];
    $db->connect($server);
    $stmt1 = $db->prepare('SELECT * FROM `userinfo`');
    $stmt2 = $db->prepare('SELECT * FROM `userinfo` WHERE id=?');
    $stmt3 = $db->prepare('SELECT `id` FROM `userinfo`');
    $prepared_num = ($db->query('show status like \'Prepared_stmt_count\''))[0]['Value'];
    echo "prepared_num: $prepared_num\n"; // 3
    $stmt1 = null;
    unset($stmt2);
    $prepared_num = ($db->query('show status like \'Prepared_stmt_count\''))[0]['Value'];
    echo "prepared_num: $prepared_num\n"; // 1
});