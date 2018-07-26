--TEST--
swoole_mysql_coro: mysql simple query

--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

go(function () {
    $mysql = new Swoole\Coroutine\MySQL();
    $res = $mysql->connect([
        'host' => MYSQL_SERVER_HOST,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ]);
    assert($res);
    $ret = $mysql->query('show tables', 2);
    assert(is_array($ret));
    assert(count($ret) > 0);
});
?>
--EXPECT--
