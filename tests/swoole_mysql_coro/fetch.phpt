--TEST--
swoole_mysql_coro: use fetch to get data
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
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
    if (!assert(is_array($ret = $stmt->fetch()) && !empty($ret))) {
        echo "FETCH1 ERROR#{$stmt->errno}: {$stmt->error}\n";
    }
    if (!assert(is_array($ret = $stmt->fetch()) && !empty($ret))) {
        echo "FETCH2 ERROR#{$stmt->errno}: {$stmt->error}\n";
    }
    assert($stmt->fetch() === null);
    assert($stmt->fetchAll() === null);
});
?>
--EXPECT--