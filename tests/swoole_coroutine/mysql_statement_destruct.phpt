--TEST--
swoole_coroutine: mysql prepare (select)
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

use Swoole\Coroutine as co;

co::create(function () {
    $db = new co\MySQL();
    $server = array(
        'host' => MYSQL_SERVER_HOST,
        'user' => MYSQL_SERVER_USER1,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB1,
    );

    $ret1 = $db->connect($server);
    if (!$ret1) {
        echo "CONNECT ERROR\n";
        return;
    }
    $stmt1 = $db->prepare('SELECT * FROM userinfo WHERE id=?');
    if (!$stmt1) {
        echo "PREPARE1 ERROR\n";
        return;
    }
    $stmt2 = $db->prepare('SELECT * FROM `userinfo`');
    if (!$stmt2) {
        echo "PREPARE2 ERROR\n";
        return;
    }
    $stmt3 = $db->prepare('SELECT `id` FROM `userinfo`');
    if (!$stmt3) {
        echo "PREPARE3 ERROR\n";
        return;
    }
    $prepared_num = (int)(($db->query('show status like \'Prepared_stmt_count\''))[0]['Value']);
    assert($prepared_num === 3);
    $stmt1 = null;
    unset($stmt2);
    $prepared_num = (int)(($db->query('show status like \'Prepared_stmt_count\''))[0]['Value']);
    assert($prepared_num === 1);
});

?>
--EXPECT--