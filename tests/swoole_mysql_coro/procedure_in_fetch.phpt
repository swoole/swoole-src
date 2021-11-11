--TEST--
swoole_mysql_coro: procedure in fetch mode
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
        'database' => MYSQL_SERVER_DB,
        'fetch_mode' => true
    ];

    $clear = <<<SQL
    DROP PROCEDURE IF EXISTS `reply`
SQL;
    $map = [
        'You said: "hello mysql!"',
        'Hey swoole!',
        'foo',
        'bar',
        'PHP is really the best programming language!'
    ];
    $procedure = <<<SQL
  CREATE DEFINER=`root`@`localhost` PROCEDURE `reply`(content varchar(255))
  BEGIN
    SELECT concat('You said: \"', content, '\"');
    SELECT '$map[1]';
    SELECT '$map[2]';
    SELECT '$map[3]';
    SELECT '$map[4]';
    INSERT INTO ckl (`domain`,`path`,`name`) VALUES ('www.baidu.com', '/search', 'baidu');
  END
SQL;

    $db->connect($server);
    if ($db->query($clear) && $db->query($procedure)) {

        //SWOOLE
        $_map = $map;
        $stmt = $db->prepare('CALL reply(?)');
        Assert::true($stmt->execute(['hello mysql!']));
        do {
            $res = $stmt->fetchAll();
            Assert::same(current($res[0]), array_shift($_map));
        } while ($ret = $stmt->nextResult());
        Assert::same($stmt->affected_rows, 1);
        Assert::assert(empty($_map), 'there are some results lost!');

        //PDO
        if (extension_loaded('PDO')) {
            $_map = $map;
            try {
                $pdo = new PDO(
                    "mysql:host=" . MYSQL_SERVER_HOST . ";port=" . MYSQL_SERVER_PORT . ";dbname=" . MYSQL_SERVER_DB . ";charset=utf8",
                    MYSQL_SERVER_USER, MYSQL_SERVER_PWD
                );
                $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
                $stmt = $pdo->prepare("CALL reply(?)");
                Assert::true($stmt->execute(['hello mysql!']));
                do {
                    $res = $stmt->fetchAll();
                    Assert::same(current($res[0]), array_shift($_map));
                } while ($ret = $stmt->nextRowset() and count($_map) > 0);
                Assert::same($stmt->rowCount(), 1, 'get the affected rows failed!');
                Assert::assert(empty($_map), 'there are some results lost!');
            } catch (\PDOException $e) {
                Assert::same($e->getCode(), 2054); // not support auth plugin
            }
        }
    }
});
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
