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
    if (!$db->query("EXPLAIN SELECT * FROM dual;")) {
        echo $db->errno . PHP_EOL;
        echo $db->error . PHP_EOL;
    }
});
?>
--EXPECT--
1096
SQLSTATE[HY000] [1096] No tables used
