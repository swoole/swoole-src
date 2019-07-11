--TEST--
swoole_mysql_coro: mysql simple query
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $mysql = new Swoole\Coroutine\MySQL();
    $res = $mysql->connect([
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ]);
    Assert::assert($res);
    $ret = $mysql->query('show tables', 2);
    Assert::assert(is_array($ret));
    Assert::assert(count($ret) > 0);
});
?>
--EXPECT--
