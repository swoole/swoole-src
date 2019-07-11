--TEST--
swoole_mysql_coro: mysql prepare (destruct)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;

co::create(function () {
    $db = new co\MySQL();
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB,
    ];

    $ret1 = $db->connect($server);

    $start_prepared_num = (int)(($db->query('show status like \'Prepared_stmt_count\''))[0]['Value']);
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

    $prepared_num1 = (int)(($db->query('show status like \'Prepared_stmt_count\''))[0]['Value']);
    Assert::same($prepared_num1 - $start_prepared_num, 3);
    $stmt1 = null; //destruct
    unset($stmt2); //destruct
    $prepared_num2 = (int)(($db->query('show status like \'Prepared_stmt_count\''))[0]['Value']);
    Assert::same($prepared_num1 - $prepared_num2, 2);
});

?>
--EXPECT--
