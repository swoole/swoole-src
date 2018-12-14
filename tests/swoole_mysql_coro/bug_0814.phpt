--TEST--
swoole_mysql_coro: mysql prepare (select)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

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
        echo "CONNECT[1] ERROR\n";
        return;
    }

    /**
     * 第一次执行prepare
     */
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
    assert(count($ret3) > 0);

    $ret = $db->query("select sleep(20)", 0.1);
    assert($ret == false);
    assert( $db->errno == SOCKET_ETIMEDOUT);
    $ret1 = $db->connect($server);
    if (!$ret1) {
        echo "CONNECT[2] ERROR\n";
        return;
    }

    /**
     * 第二次执行prepare
     */
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
    assert(count($ret3) > 0);
});

?>
--EXPECT--