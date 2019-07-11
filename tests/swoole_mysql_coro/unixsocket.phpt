--TEST--
swoole_mysql_coro: mysql connection on unix socket
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
require __DIR__ . '/../include/config.php';
skip_if_file_not_exist(MYSQL_SERVER_PATH);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $db = new Swoole\Coroutine\Mysql;
    $server = [
        'host' => 'unix:/' . MYSQL_SERVER_PATH,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ];
    Assert::assert($db->connect($server));
    Assert::same($db->query('SELECT 1'), [['1' => '1']]);
    echo "DONE\n";
});
?>
--EXPECTF--
DONE
