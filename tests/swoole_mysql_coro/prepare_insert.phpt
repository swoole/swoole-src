--TEST--
swoole_mysql_coro: mysql prepare (insert)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;

co::create(function () {
    $db = new co\MySQL();
    $server = array(
        'host' => MYSQL_SERVER_HOST,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB,
    );

    $ret1 = $db->connect($server);
    if (!$ret1) {
        echo "CONNECT ERROR\n";
        return;
    }

    $stmt = $db->prepare('INSERT INTO ckl (`domain`,`path`,`name`) VALUES (?,?,?)');
    if (!$stmt) {
        echo "PREPARE ERROR\n";
        return;
    }

    $ret3 = $stmt->execute(array('www.baidu.com', '/search', 'baidu'));
    if (!$ret3) {
        echo "EXECUTE ERROR\n";
        return;
    }
    assert($stmt->insert_id > 0);
});

?>
--EXPECT--