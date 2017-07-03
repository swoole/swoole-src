<?php
/**
 * Created by PhpStorm.
 * User: marsnowxiao
 * Date: 2017/4/27
 * Time: 下午4:34
 */
require_once __DIR__ . "/../../../include/bootstrap.php";

/**
 * CREATE TABLE zan_test (
relation_id int(10) unsigned NOT NULL AUTO_INCREMENT,
market_id int(10) NOT NULL,
goods_id int(10) NOT NULL,
PRIMARY KEY (relation_id)
);
 */
class swoole_mysql_transaction_rollback
{
    private $swoole_mysql;
    private $timeout;
    private $nRecords;

    function __construct()
    {
        $this->swoole_mysql = new \swoole_mysql();

        $this->swoole_mysql->on("close", function () {
            // echo "closed\n";
        });
    }

    function verify_callback(\swoole_mysql $swoole_mysql, $result)
    {
        swoole_timer_clear($this->timeout);
        assert($swoole_mysql->errno === 0);
        assert(intval($result[0]['cnt']) === $this->nRecords);
        fprintf(STDERR, "SUCCESS");
        swoole_event_exit();
    }

    function rollback_callback(\swoole_mysql $swoole_mysql)
    {
        swoole_timer_clear($this->timeout);
        assert($swoole_mysql->errno === 0);

        $this->timeout = swoole_timer_after(1000, function () {
            assert(false, "verify timeout");
        });
        $sql = "SELECT COUNT(1) AS cnt FROM zan_test WHERE market_id = 1 AND goods_id = 2";
        $swoole_mysql->query($sql, [$this, "verify_callback"]);
    }

    function insert_callback(\swoole_mysql $swoole_mysql, $result)
    {
        swoole_timer_clear($this->timeout);
        assert($swoole_mysql->errno === 0);

        $this->timeout = swoole_timer_after(1000, function () {
            assert(false, "rollback timeout");
        });
        $swoole_mysql->rollback([$this, "rollback_callback"]);
    }


    function query_callback(\swoole_mysql $swoole_mysql, $result)
    {
        swoole_timer_clear($this->timeout);
        assert($swoole_mysql->errno === 0);
        $this->nRecords = intval($result[0]['cnt']);

        $this->timeout = swoole_timer_after(1000, function () {
            assert(false, "query timeout");
        });

        $sql = "insert into zan_test(market_id, goods_id) value(1, 2)";

        $swoole_mysql->query($sql, [$this, "insert_callback"]);
    }

    function begin_callback(\swoole_mysql $swoole_mysql)
    {
        swoole_timer_clear($this->timeout);
        assert($swoole_mysql->errno === 0);

        $this->timeout = swoole_timer_after(1000, function () {
            assert(false, "query timeout");
        });
        $sql = "SELECT COUNT(1) AS cnt FROM zan_test WHERE market_id = 1 AND goods_id = 2";
        $swoole_mysql->query($sql, [$this, "query_callback"]);
    }

    function connect_callback(\swoole_mysql $swoole_mysql, $result)
    {
        swoole_timer_clear($this->timeout);
        if ($result) {
            $this->timeout = swoole_timer_after(1000, function () {
                assert(false, "begin timeout");
            });
            $swoole_mysql->begin([$this, "begin_callback"]);
        } else {
            echo "connect error [errno=$swoole_mysql->connect_errno, error=$swoole_mysql->connect_error]";
        }
    }

    function run()
    {
        $this->timeout = swoole_timer_after(1000, function () {
            assert(false, "connect timeout");
        });
        $this->swoole_mysql->connect([
            "host" => MYSQL_SERVER_HOST,
            "port" => MYSQL_SERVER_PORT,
            "user" => MYSQL_SERVER_USER,
            "password" => MYSQL_SERVER_PWD,
            "database" => MYSQL_SERVER_DB,
            "charset" => "utf8mb4",
        ], [$this, "connect_callback"]);

    }
}

$mysql = new swoole_mysql_transaction_rollback();
$mysql->run();
