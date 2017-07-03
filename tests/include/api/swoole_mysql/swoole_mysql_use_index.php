<?php
/**
 * Created by PhpStorm.
 * User: marsnowxiao
 * Date: 2017/5/9
 * Time: 下午2:34
 */
require_once __DIR__ . "/swoole_mysql_init.php";

swoole_mysql_query("select * from zan_test", function($swoole_mysql, $result) {
    assert($swoole_mysql->errno === 0);
    assert($swoole_mysql->isUsedIndex() === false);
    swoole_mysql_query("select relation_id from zan_test", function($swoole_mysql, $result) {
        assert($swoole_mysql->errno === 0);
        assert($swoole_mysql->isUsedIndex() === true);
        fprintf(STDERR, "SUCCESS");
        swoole_event_exit();
    });
});