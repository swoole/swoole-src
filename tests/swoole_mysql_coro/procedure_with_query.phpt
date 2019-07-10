--TEST--
swoole_mysql_coro: procedure without query (#2117)
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
        for ($n = MAX_REQUESTS_LOW; $n--;) {
            $res = $db->query('CALL reply("hello mysql!")');
            $_map = $map;
            do {
                Assert::same(current($res[0]), array_shift($_map));
            } while ($res = $db->nextResult());
        }
        for ($n = MAX_REQUESTS_LOW; $n--;) {
            $res = $db->query('CALL reply("hello mysql!")');
            $_map = $map;
            do {
                Assert::same(current($res[0]), array_shift($_map));
            } while ($res = $db->nextResult());
            Assert::same($db->affected_rows, 1, 'get the affected rows failed!');
            Assert::assert(empty($_map), 'there are some results lost!');
        }
    }

    echo "DONE\n";
});
?>
--EXPECT--
DONE
