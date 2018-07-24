--TEST--
swoole_mysql_coro: use fetch to get data
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/../include/config.php';
go(function () {
    $db = new Swoole\Coroutine\Mysql;
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB,
        'fetch_mode' => true
    ];

    $db->connect($server);

    // now we can make the responses independent
    $stmt = $db->prepare('SELECT `id` FROM `userinfo` LIMIT 2');
    assert($stmt->execute() === true);
    assert(is_array($stmt->fetch()));
    assert(is_array($stmt->fetch()));
    assert($stmt->fetch() === null);
    assert($stmt->fetchAll() === null);
});
?>
--EXPECT--