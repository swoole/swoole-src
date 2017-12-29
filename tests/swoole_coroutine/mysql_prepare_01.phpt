--TEST--
swoole_coroutine: mysql prepare (insert)
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

    $ret2 = $db->prepare('INSERT INTO ckl (`domain`,`path`,`name`) VALUES (?,?,?)');
    if (!$ret2) {
        echo "PREPARE ERROR\n";
        return;
    }

    $ret3 = $db->execute(array('www.baidu.com', '/search', 'baidu'));
    if (!$ret3) {
        echo "EXECUTE ERROR\n";
        return;
    }
    assert($db->insert_id > 0);
});

?>
--EXPECT--