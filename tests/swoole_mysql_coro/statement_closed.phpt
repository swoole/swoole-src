--TEST--
swoole_mysql_coro: mysql prepare (destruct)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $db = new Co\MySQL();
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ];
    $ret = $db->connect($server);
    assert($ret);
    $statement = $db->prepare('SELECT 1');
    assert($statement instanceof Co\Mysql\Statement);
    $ret = $statement->execute();
    assert($ret[0][1] === 1);
    $db->close();
    $ret = $db->connect($server);
    assert($ret);
    $ret = $statement->execute();
    assert(!$ret);
});
?>
--EXPECT--
