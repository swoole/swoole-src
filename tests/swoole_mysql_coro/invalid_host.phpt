--TEST--
swoole_mysql_coro: invalid host
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $mysql = new Co\MySQL;
    $connected = $mysql->connect([
        'host' => get_safe_random(),
        'port' => MYSQL_SERVER_PORT,
        'database' => MYSQL_SERVER_DB,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'timeout' => 0.5
    ]);
    echo 'Connection: ' . ($connected ? 'Connected' : 'Not connected') . PHP_EOL;
    Assert::same($mysql->connect_errno, SWOOLE_MYSQLND_CR_CONNECTION_ERROR);
    echo $mysql->connect_error . PHP_EOL;
});
?>
--EXPECTF--
Connection: Not connected
SQLSTATE[HY000] [2002] %s
