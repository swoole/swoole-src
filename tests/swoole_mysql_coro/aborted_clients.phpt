--TEST--
swoole_mysql_coro: mysql-close/reconnect/aborted-client-num
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $db = new Swoole\Coroutine\Mysql;
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ];
    Assert::true($db->connect($server));
    $before_num = (int)$db->query('show status like "Aborted_clients"')[0]["Value"];
    Assert::true($db->close());
    Assert::true($db->connect($server));
    $after_num = (int)$db->query('show status like "Aborted_clients"')[0]["Value"];
    Assert::same($after_num - $before_num, 0);
});
?>
--EXPECT--
