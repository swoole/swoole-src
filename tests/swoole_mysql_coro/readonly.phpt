--TEST--
swoole_mysql_coro: mysql use readonly user
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_mysql8();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $root = new Swoole\Coroutine\Mysql;
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ];
    $connected = $root->connect($server);
    Assert::assert($connected);

    // create read only user
    $create = $root->query('CREATE USER `readonly`@`%` IDENTIFIED BY \'123456\';');
    Assert::assert($create);
    $grant = $root->query('GRANT SELECT ON *.* TO `readonly`@`%` WITH GRANT OPTION;');
    Assert::assert($grant);

    // use readonly
    $server['user'] = 'readonly';
    $server['password'] = '123456';
    $readonly = new Swoole\Coroutine\MySQL;
    $connected = $readonly->connect($server);
    Assert::assert($connected);

    // read
    $result = $readonly->query('SELECT * FROM userinfo');
    Assert::assert(is_array($result) && count($result) > 5);
    $id = $result[0]['id'];
    // write
    $delete = $readonly->query('DELETE FROM userinfo WHERE id=' . $id);
    Assert::assert(!$delete);
    echo $readonly->errno . "\n";
    echo $readonly->error . "\n";

    // drop
    Assert::assert($root->query('DROP ROLE readonly'));
});
swoole_event::wait();
?>
--EXPECTF--
1142
SQLSTATE[42000] [1142] DELETE command denied to user 'readonly'@'%s' for table 'userinfo'
