<?php

require_once __DIR__ . "/swoole_mysql_init.php";


//$sql = "insert into ad (`kdt_id`, `num`, `data`, `valid`, `created_time`, `update_time`) VALUES (?,?,?,?,?,?)";
//$bind = [99999, 1, "data", 1, 0, 0];

$sql = "insert into ad (`kdt_id`, `num`, `data`, `valid`, `created_time`, `update_time`) VALUES (99999, 1, 'data', 1, 0, 0)";


swoole_mysql_query($sql, function($swoole_mysql, $result) {
    assert($swoole_mysql->errno === 0);
    assert($result === true);
    assert($swoole_mysql->insert_id > 0);

    $swoole_mysql->query("select 1", function($swoole_mysql, $result) {
        assert($swoole_mysql->errno === 0);
        assert(!empty($result));
        swoole_event_exit();
        fprintf(STDERR, "SUCCESS");
    });
});