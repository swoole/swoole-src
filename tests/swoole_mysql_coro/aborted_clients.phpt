--TEST--
swoole_mysql_coro: mysql-close/reconnect/aborted-client-num
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
go(function () {
    $db = new Swoole\Coroutine\Mysql;
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ];
    assert($db->connect($server) === true);
    $before_num = (int)$db->query('show status like "Aborted_clients"')[0]["Value"];
    assert($db->close() === true);
    assert($db->connect($server) === true);
    $after_num = (int)$db->query('show status like "Aborted_clients"')[0]["Value"];
    assert($after_num - $before_num === 0);
});
?>
--EXPECT--