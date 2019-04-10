--TEST--
swoole_mysql_coro: ERR Instead of EOF 
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
    $db->connect($server);

    $res = $db->query("EXPLAIN SELECT * FROM dual;");
    assert(!$res);
    Assert::eq($db->errno, 1096);
    Assert::eq($db->error, "No tables used");
});
?>
--EXPECT--