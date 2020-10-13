--TEST--
swoole_mysql_coro: mysql db destruct
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co\Run(function () {
    $db = new Co\MySQL();
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ];
    $ret = $db->connect($server);
    if (Assert::true($ret)) {
        $statement = $db->prepare('SELECT 1');
        Assert::isInstanceOf($statement, Co\Mysql\Statement::class);
        $ret = $statement->execute();
        Assert::same($ret[0][1], 1);
        echo "DONE\n";
    }
});
?>
--EXPECT--
DONE
