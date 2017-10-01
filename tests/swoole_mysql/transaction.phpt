--TEST--
swoole_mysql: transaction begin & commit
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

$swoole_mysql = new \swoole_mysql();

$swoole_mysql->on("close", function ()
{
    echo "closed\n";
});

$swoole_mysql->connect([
    "host" => MYSQL_SERVER_HOST,
    "port" => MYSQL_SERVER_PORT,
    "user" => MYSQL_SERVER_USER,
    "password" => MYSQL_SERVER_PWD,
    "database" => MYSQL_SERVER_DB,
    "charset" => "utf8mb4",
], function (\swoole_mysql $swoole_mysql, $result)
{
    if ($result)
    {
        $swoole_mysql->begin(function (\swoole_mysql $swoole_mysql)
        {
            assert($swoole_mysql->errno === 0);
            $sql = "SELECT COUNT(*) AS cnt FROM userinfo";
            $swoole_mysql->query($sql, function (\swoole_mysql $swoole_mysql, $result)
            {
                assert($swoole_mysql->errno === 0);
                $sql = "UPDATE  `userinfo` SET `level` =  '11' WHERE `id` = 4; ";
                $swoole_mysql->query($sql, function (\swoole_mysql $swoole_mysql, $result)
                {
                    $swoole_mysql->commit(function (\swoole_mysql $swoole_mysql)
                    {
                        $sql = "SELECT * FROM `userinfo` where `id` = 4;";
                        $swoole_mysql->query($sql, function (\swoole_mysql $swoole_mysql, $result)
                        {
                            assert($swoole_mysql->errno === 0);
                            assert(intval($result[0]['level']) === 11);
                            echo "SUCCESS\n";
                            $swoole_mysql->close();
                        });
                    });
                });
            });
        });
    }
    else
    {
        echo "connect error [errno=$swoole_mysql->connect_errno, error=$swoole_mysql->connect_error]";
    }
});
Swoole\Event::wait();
?>
--EXPECT--
SUCCESS
closed