<?php
/**
 * Created by PhpStorm.
 * User: marsnowxiao
 * Date: 2017/4/27
 * Time: 下午4:01
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
        $result = $swoole_mysql->begin(function(\swoole_mysql $swoole_mysql) {
            swoole_timer_clear($swoole_mysql->begin_timeout);
            assert($swoole_mysql->errno === 0);

            $swoole_mysql->begin_timeout = swoole_timer_after(1000, function() {
                assert(false, "begin timeout");
            });
            try {
                $swoole_mysql->begin(function(\swoole_mysql $swoole_mysql) {
                    assert(false, "begin callback");
                });
                assert(false, "begin twice exception is expected");
            } catch (\Exception $e) {
                swoole_timer_clear($swoole_mysql->begin_timeout);
                fprintf(STDERR, "SUCCESS");
            }
            swoole_event_exit();
        });
        assert($result === true, "Transaction begin failed");
    } else {
        echo "connect error [errno=$swoole_mysql->connect_errno, error=$swoole_mysql->connect_error]";
    }
});