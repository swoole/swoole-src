--TEST--
swoole_mysql_coro: just execute (test memory leak)
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_unsupported();
?>
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
        'database' => MYSQL_SERVER_DB,
        'fetch_mode' => true
    ];

    $db->connect($server);
    $stmt = $db->prepare('SELECT * FROM `userinfo` LIMIT 1');
    Assert::true($stmt->execute());
    Assert::true($stmt->execute());
    Assert::true($stmt->execute());
    Assert::assert(is_array($stmt->fetchAll()));
});
?>
--EXPECT--
