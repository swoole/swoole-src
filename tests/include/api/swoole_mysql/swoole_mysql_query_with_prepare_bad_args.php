<?php
/**
 * Created by PhpStorm.
 * User: marsnowxiao
 * Date: 2017/4/28
 * Time: 下午5:08
 */
require_once __DIR__ . "/../../../include/bootstrap.php";

error_reporting(E_ALL);
assert_options(ASSERT_BAIL, true);

$swoole_mysql = new \swoole_mysql();

$swoole_mysql->on("close", function() {
    // echo "closed\n";
});

$swoole_mysql->conn_timeout = swoole_timer_after(5000, function() {
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
        $warning = error_get_last();
        assert(is_null($warning), "program should start without warnings");

        $swoole_mysql->query_timeout = swoole_timer_after(5000, function() {
            assert(false, "query timeout");
        });
        $sql = "SELECT COUNT(1) AS cnt FROM zan_test WHERE market_id = :market_id AND goods_id = :goods_id";
        $arr = [];
        @$swoole_mysql->query($sql, $arr, function(\swoole_mysql $swoole_mysql, $result) {
            assert(false, "query callback should not execute");
        });

        swoole_timer_clear($swoole_mysql->query_timeout);
        $warning = error_get_last();
        assert(!is_null($warning), "an warning is expected");
        error_clear_last();

        $swoole_mysql->query_timeout = swoole_timer_after(5000, function() {
            assert(false, "query timeout");
        });
        $arr = ["market_id" => 1, "other_id" => 2];
        @$swoole_mysql->query($sql, $arr, function(\swoole_mysql $swoole_mysql, $result) {
            assert(false, "query callback should not execute");
        });
        swoole_timer_clear($swoole_mysql->query_timeout);
        $warning = error_get_last();
        assert(!is_null($warning), "an warning is expected");
        error_clear_last();

        $swoole_mysql->query_timeout = swoole_timer_after(5000, function() {
            assert(false, "query timeout");
        });
        $arr = ["market_id" => 1, "goods_id" => 2, "other_id" => 3];
        @$swoole_mysql->query($sql, $arr, function(\swoole_mysql $swoole_mysql, $result) {
            assert(false, "query callback should not execute");
        });
        swoole_timer_clear($swoole_mysql->query_timeout);
        $warning = error_get_last();
        assert(!is_null($warning), "an warning is expected");
        error_clear_last();

        $swoole_mysql->query_timeout = swoole_timer_after(5000, function() {
            assert(false, "query timeout");
        });
        $sql = "SELECT COUNT(1) AS cnt FROM zan_test WHERE market_id = ? AND goods_id = :goods_id";
        $arr = [1, "goods_id" => 2];

        @$swoole_mysql->query($sql, $arr, function(\swoole_mysql $swoole_mysql, $result) {
            assert(false, "query callback should not execute");
        });
        $warning = error_get_last();
        assert(!is_null($warning), "an warning is expected");
        error_clear_last();

        $sql = "SELECT COUNT(1) AS cnt FROM zan_test";
        $arr = [1, "goods_id" => 2];

        $swoole_mysql->query_timeout = swoole_timer_after(5000, function() {
            assert(false, "query timeout");
        });
        @$swoole_mysql->safe_query($sql, $arr, function(\swoole_mysql $swoole_mysql, $result) {
            swoole_timer_clear($swoole_mysql->query_timeout);
            assert($swoole_mysql->errno === 0);
            fprintf(STDERR, "SUCCESS");
            swoole_event_exit();
        });
        $warning = error_get_last();
        assert(is_null($warning), "warning is not permitted");
        error_clear_last();

    } else {
        echo "connect error [errno=$swoole_mysql->connect_errno, error=$swoole_mysql->connect_error]";
    }
});