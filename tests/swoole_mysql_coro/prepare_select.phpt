--TEST--
swoole_mysql_coro: mysql prepare (select)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co\run(function () {
    $db = new Co\MySQL();
    $server = array(
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB,
    );

    $ret1 = $db->connect($server);
    if (!$ret1) {
        echo "CONNECT ERROR\n";
        return;
    }

    $stmt = $db->prepare('SELECT * FROM userinfo WHERE id=?');
    if (!$stmt) {
        echo "PREPARE ERROR\n";
        return;
    }

    $ret3 = $stmt->execute([5]);
    if (!$ret3) {
        echo "EXECUTE ERROR#{$stmt->errno}: {$stmt->error}\n";
        return;
    }
    Assert::assert(count($ret3) > 0);
});

?>
--EXPECT--
