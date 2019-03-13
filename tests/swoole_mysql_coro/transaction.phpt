--TEST--
swoole_mysql_coro: transaction
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
error_reporting(E_DEPRECATED);
go(function () {
    $db = new Swoole\Coroutine\Mysql;
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ];
    $db->connect($server);

    $random = mt_rand();
    assert($db->begin());
    assert($db->query('INSERT INTO ckl (`domain`,`path`,`name`) VALUES ("www.swoole.com", "/", "' . $random . '")'));
    assert(!empty($db->query('SELECT `name` FROM `ckl` WHERE `name`="' . $random . '"')));
    assert($db->rollback());
    assert(empty($db->query('SELECT `name` FROM `ckl` WHERE `name`="' . $random . '"')));
    $random = mt_rand();
    assert($db->begin());
    assert($db->query('INSERT INTO ckl (`domain`,`path`,`name`) VALUES ("www.swoole.com", "/", "' . $random . '")'));
    assert($db->commit());
    assert(!empty($db->query('SELECT `name` FROM `ckl` WHERE `name`="' . $random . '"')));
    assert($db->query('DELETE FROM `ckl` WHERE `name`="' . $random . '"'));
    assert(empty($db->query('SELECT `name` FROM `ckl` WHERE `name`="' . $random . '"')));

    $db->setDefer();
    assert(!$db->begin());
    assert(!$db->getDefer());
    $db->setDefer();
    assert(!$db->commit());
    assert(!$db->getDefer());
    $db->setDefer();
    assert(!$db->begin());
    assert(!$db->getDefer());
    $db->setDefer();
    assert(!$db->rollback());
    assert(!$db->getDefer());
});
?>
--EXPECTF--
Deprecated: Swoole\Coroutine\MySQL::%s(): %s. in %s on line %d

Deprecated: Swoole\Coroutine\MySQL::%s(): %s. in %s on line %d

Deprecated: Swoole\Coroutine\MySQL::%s(): %s. in %s on line %d

Deprecated: Swoole\Coroutine\MySQL::%s(): %s. in %s on line %d
