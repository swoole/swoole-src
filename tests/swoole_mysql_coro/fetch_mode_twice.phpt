--TEST--
fetch_mode_twice: call fetch twice
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
        'user' => MYSQL_SERVER_USER1,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB1,
        'fetch_mode' => true
    ];

    $db->connect($server);

    assert($db->query("INSERT INTO ckl (`domain`,`path`,`name`) VALUES ('www.baidu.com', '/search', 'baidu')") === true);
    // now we can make the responses independent
    $stmt = $db->prepare('SELECT * FROM ckl LIMIT 1');
    assert($stmt->execute() === true);
    assert(($ret = $stmt->fetchAll()) && is_array($ret) && count($ret) === 1);
    assert($stmt->fetchAll() === null);
});
?>
--EXPECT--