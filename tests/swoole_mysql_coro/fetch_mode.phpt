--TEST--
fetch_mode: use fetch to get data
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
go(function () {
    $db = new Swoole\Coroutine\Mysql;
    $server = [
        'host' => '127.0.0.1',
        'user' => 'root',
        'password' => 'root',
        'database' => 'test',
        'fetch_mode' => true
    ];

    $db->connect($server);

    // now we can make the responses independent
    $stmt1 = $db->prepare('SELECT * FROM ckl LIMIT 1');
    assert($stmt1->execute() === true);
    $stmt2 = $db->prepare('SELECT * FROM ckl LIMIT 2');
    assert($stmt2->execute() === true);
    assert(count($stmt1->fetchAll()) === 1);
    assert(count($stmt2->fetchAll()) === 2);
});
?>
--EXPECT--