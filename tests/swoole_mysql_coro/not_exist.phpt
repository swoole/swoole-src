--TEST--
swoole_mysql_coro: mysql connect to wrong database
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
        'database' => 'not_exist'
    ];
    $connected = $db->connect($server);
    Assert::assert(!$connected);
    Assert::same($db->connect_errno, 1049); // unknown database
    Assert::assert(strpos($db->connect_error, 'not_exist'));
});
?>
--EXPECT--
