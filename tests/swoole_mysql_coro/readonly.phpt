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
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ];
    $connected = $root->connect($server);
    assert($connected);

    // create read only user
    $create = $root->query('CREATE USER `readonly`@`%` IDENTIFIED BY \'123456\';');
    assert($create);
    $grant = $root->query('GRANT SELECT ON *.* TO `readonly`@`%` WITH GRANT OPTION;');
    assert($grant);

    // use readonly
    $server['user'] = 'readonly';
    $server['password'] = '123456';
    $readonly = new Swoole\Coroutine\MySQL;
    $connected = $readonly->connect($server);
    assert($connected);

    // read
    $result = $readonly->query('SELECT * FROM userinfo');
    assert(is_array($result) && count($result) > 5);
    $id = $result[0]['id'];
    // write
    $delete = $readonly->query('DELETE FROM userinfo WHERE id=' . $id);
    assert(!$delete);
    echo $readonly->errno . "\n";
    echo $readonly->error . "\n";

    // drop
    assert($root->query('DROP ROLE readonly'));
});
?>
--EXPECTF--
1142
DELETE command denied to user 'readonly'@'%s' for table 'userinfo'
