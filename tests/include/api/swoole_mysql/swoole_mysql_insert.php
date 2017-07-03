<?php
require_once __DIR__ . "/swoole_mysql_init.php";

$sql = "INSERT INTO `test`.`userinfo` (`name`, `level`, `passwd`, `regtime`, `big_n`, `lastlogin_ip`)
  VALUES ('hello', '99', '123456', CURRENT_TIMESTAMP, '99999999', '');";

swoole_mysql_query($sql, function ($swoole_mysql, $result)
{
    ob_start();
    assert($result === true);
    assert($swoole_mysql->errno === 0);
    if ($buf = ob_get_clean())
    {
        fprintf(STDERR, $buf);
    }
    assert($swoole_mysql->insert_id > 0);
    swoole_event_exit();
    fprintf(STDERR, "SUCCESS\n");
});
