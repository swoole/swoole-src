--TEST--
swoole_mysql_coro: query 'CALL' statement & prepare (#2117)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $db = new Swoole\Coroutine\Mysql;
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ];

    $clear = <<<SQL
    DROP PROCEDURE IF EXISTS `sp_whoami`
SQL;
    $procedure = <<<SQL
  CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_whoami`()
  BEGIN
    SELECT user();
  END
SQL;

    $db->connect($server);
    if ($db->query($clear) && $db->query($procedure)) {
        $db->query('CALL sp_whoami()');
        Assert::null($db->nextResult());
        $stmt = $db->prepare('CALL sp_whoami()');
        $ret = $stmt->execute();
        Assert::assert(strpos(current($ret[0]), MYSQL_SERVER_USER) !== false);
        Assert::null($stmt->nextResult());
    }
});
?>
--EXPECT--
