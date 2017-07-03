<?php
/**
 * Created by PhpStorm.
 * User: marsnowxiao
 * Date: 2017/4/20
 * Time: 上午11:19
 */
require_once __DIR__ . "/../../../include/bootstrap.php";

$swoole_mysql = new \swoole_mysql();

$swoole_mysql->on("close", function() {
    // echo "closed\n";
});

$swoole_mysql->conn_timeout = swoole_timer_after(1000, function() {
    assert(false, "connect timeout");
});

/**
 * CREATE TABLE zan_test (
relation_id int(10) unsigned NOT NULL AUTO_INCREMENT,
market_id int(10) NOT NULL,
goods_id int(10) NOT NULL,
PRIMARY KEY (relation_id)
);
 */
$swoole_mysql->connect([
    "host" => MYSQL_SERVER_HOST,
    "port" => MYSQL_SERVER_PORT,
    "user" => MYSQL_SERVER_USER,
    "password" => MYSQL_SERVER_PWD,
    "database" => MYSQL_SERVER_DB,
    "charset" => "utf8mb4",
], function(\swoole_mysql $swoole_mysql, $result) {
    swoole_timer_clear($swoole_mysql->conn_timeout);

    if ($result) {
        $swoole_mysql->begin_timeout = swoole_timer_after(1000, function() {
            assert(false, "begin timeout");
        });
        $swoole_mysql->begin(function(\swoole_mysql $swoole_mysql) {
            swoole_timer_clear($swoole_mysql->begin_timeout);
            assert($swoole_mysql->errno === 0);

            $swoole_mysql->query_timeout = swoole_timer_after(1000, function() {
                assert(false, "query timeout");
            });
            $sql = "SELECT COUNT(1) AS cnt FROM zan_test WHERE market_id = 1 AND goods_id = 2";
            $swoole_mysql->query($sql, function(\swoole_mysql $swoole_mysql, $result) {
                swoole_timer_clear($swoole_mysql->query_timeout);
                assert($swoole_mysql->errno === 0);
                $count = intval($result[0]['cnt']);

                $swoole_mysql->query_timeout = swoole_timer_after(1000, function() {
                    assert(false, "query timeout");
                });

                $sql = "insert into zan_test(market_id, goods_id) value(1, 2)";

                $swoole_mysql->query($sql, function(\swoole_mysql $swoole_mysql, $result) use ($count) {
                    swoole_timer_clear($swoole_mysql->query_timeout);
                    assert($swoole_mysql->errno === 0);

                    $swoole_mysql->commit_timeout = swoole_timer_after(1000, function() {
                        assert(false, "commit timeout");
                    });

                    $swoole_mysql->commit(function(\swoole_mysql $swoole_mysql) use($count) {
                        swoole_timer_clear($swoole_mysql->commit_timeout);
                        assert($swoole_mysql->errno === 0);

                        $swoole_mysql->query_timeout = swoole_timer_after(1000, function() {
                            assert(false, "query timeout");
                        });
                        $sql = "SELECT COUNT(1) AS cnt FROM zan_test WHERE market_id = 1 AND goods_id = 2";
                        $swoole_mysql->query($sql, function(\swoole_mysql $swoole_mysql, $result) use ($count) {
                            swoole_timer_clear($swoole_mysql->query_timeout);
                            assert($swoole_mysql->errno === 0);
                            assert(intval($result[0]['cnt']) === $count + 1);
                            fprintf(STDERR, "SUCCESS");
                            swoole_event_exit();
                        });
                    });
                });
            });
        });
    } else {
        echo "connect error [errno=$swoole_mysql->connect_errno, error=$swoole_mysql->connect_error]";
    }
});