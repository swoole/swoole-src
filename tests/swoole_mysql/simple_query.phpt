--TEST--
swoole_mysql: simple query
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/swoole_mysql/swoole_mysql_init.php';

swoole_mysql_query("select * from userinfo limit 2", function($mysql, $result) {
    assert($mysql->errno === 0);
    assert(is_array($result) and count($result) == 2);
    echo "SUCCESS\n";
    $mysql->close();
});
?>
--EXPECT--
SUCCESS
closed