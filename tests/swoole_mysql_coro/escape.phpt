--TEST--
swoole_mysql_coro: mysql escape
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function(){
    $mysql = new Swoole\Coroutine\MySQL();
        $res = $mysql->connect([
            'host' => MYSQL_SERVER_HOST,
            'port' => MYSQL_SERVER_PORT,
            'user' => MYSQL_SERVER_USER,
            'password' => MYSQL_SERVER_PWD,
            'database' => MYSQL_SERVER_DB
        ]);
        Assert::same($mysql->escape(""), "");
});
?>
--EXPECT--
