<?php

require_once __DIR__ . "/swoole_mysql_init.php";

//$pdo = new \PDO("swoole_mysql:dbname=showcase;host=127.0.0.1", "test_database", "test_database");
//$ret = $pdo->query("select 1, 1");
//var_dump($ret->fetchAll());
//exit;

//$link = new \mysqli();
//swoole_mysql_query();
//$link->connect(MYSQL_SERVER_HOST, MYSQL_SERVER_USER, MYSQL_SERVER_PWD, MYSQL_SERVER_DB, MYSQL_SERVER_PORT);
//$ret = $link->query("select 1, 1");
//$ret = $link->query("select * from ad");
//var_dump($ret);
//var_dump(mysqli_fetch_assoc($ret));
//var_dump(mysqli_fetch_field($ret));
//var_dump(mysqli_fetch_all($ret));
//exit;


swoole_mysql_query("select 1, 1", function($swoole_mysql, $result) {
    assert($swoole_mysql->errno === 0);
    var_dump($result);
    assert(count($result[0]) === 2);
    swoole_event_exit();
});