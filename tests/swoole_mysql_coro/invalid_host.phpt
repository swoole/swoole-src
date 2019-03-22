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
        'host' => 'invalid_host',
        'port' => MYSQL_SERVER_PORT,
        'database' => MYSQL_SERVER_DB,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'timeout' => 0.5
    ]);
    echo 'Connection: ' . ($connected ? 'Connected' : 'Not connected') . PHP_EOL;
    echo 'Errno: ' . $mysql->connect_errno . PHP_EOL;
    echo 'Error: ' . $mysql->connect_error . PHP_EOL;
});
?>
--EXPECT--
Connection: Not connected
Errno: 704
Error: DNS Lookup resolve failed
