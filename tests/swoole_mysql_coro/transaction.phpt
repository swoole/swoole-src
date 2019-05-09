--TEST--
swoole_mysql_coro: transaction
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\MySQL\Exception;

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
    Assert::assert($db->begin());
    Assert::assert($db->query('INSERT INTO ckl (`domain`,`path`,`name`) VALUES ("www.swoole.com", "/", "' . $random . '")'));
    Assert::assert(!empty($db->query('SELECT `name` FROM `ckl` WHERE `name`="' . $random . '"')));
    Assert::assert($db->rollback());
    Assert::assert(empty($db->query('SELECT `name` FROM `ckl` WHERE `name`="' . $random . '"')));
    $random = mt_rand();
    Assert::assert($db->begin());
    Assert::assert($db->query('INSERT INTO ckl (`domain`,`path`,`name`) VALUES ("www.swoole.com", "/", "' . $random . '")'));
    Assert::assert($db->commit());
    Assert::assert(!empty($db->query('SELECT `name` FROM `ckl` WHERE `name`="' . $random . '"')));
    Assert::assert($db->query('DELETE FROM `ckl` WHERE `name`="' . $random . '"'));
    Assert::assert(empty($db->query('SELECT `name` FROM `ckl` WHERE `name`="' . $random . '"')));

    $db->setDefer();
    Assert::throws(function () use ($db) { $db->begin(); }, Exception::class);
    Assert::throws(function () use ($db) { $db->commit(); }, Exception::class);
    Assert::throws(function () use ($db) { $db->rollback(); }, Exception::class);
    echo "DONE\n";
});
?>
--EXPECT--
DONE
