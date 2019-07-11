--TEST--
swoole_mysql_coro: mysql procedure single
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
    DROP PROCEDURE IF EXISTS `say`
SQL;
    $procedure = <<<SQL
  CREATE DEFINER=`root`@`localhost` PROCEDURE `say`(content varchar(255))
  BEGIN
    SELECT concat('You said: \"', content, '\"');
  END
SQL;

    $db->connect($server);
    if ($db->query($clear) && $db->query($procedure)) {
        $stmt = $db->prepare('CALL say(?)');
        for ($n = MAX_REQUESTS; $n--;) {
            $ret = $stmt->execute(['hello mysql!']);
            Assert::same(current($ret[0]), 'You said: "hello mysql!"');
            Assert::null($stmt->nextResult());
        }
    }
});
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
