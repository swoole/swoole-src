--TEST--
swoole_mysql_coro: mysql connect with wrong password
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
        'password' => 'i am hack',
        'database' => MYSQL_SERVER_DB
    ];
    $connected = $db->connect($server);
    Assert::assert(!$connected);
    echo $db->connect_errno . "\n";
    echo $db->connect_error, "\n";
});
?>
--EXPECTF--
1045
SQLSTATE[28000] [1045] Access denied for user 'root'@'%s' (using password: YES)
