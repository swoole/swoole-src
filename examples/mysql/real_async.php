<?php
if (!function_exists('swoole_get_mysqli_sock'))
{
    die("no async_mysql support\n");
}
$db = new mysqli;
$db->connect('127.0.0.1', 'root', 'root', 'test');
//$sql1 =  "UPDATE  `test`.`userinfo` SET  `passwd` =  '888888' WHERE  `userinfo`.`id` =2";
//$sql2 = "INSERT INTO `test`.`userinfo` (`id`, `name`, `passwd`, `regtime`, `lastlogin_ip`) VALUES (NULL, 'jack', 'xuyou', CURRENT_TIMESTAMP, '');";
//$sql2 = "DELETE FROM `test`.`userinfo` WHERE `userinfo`.`id` = 23;";
$sql2 = "SELECT * FROM  `userinfo` LIMIT 0, 100";

//swoole_mysql_query($db, $sql2);
//swoole_event_add(swoole_get_mysqli_sock($db), function($__db_sock) {
//    global $db;
//    $s = microtime(true);
//    $r = swoole_mysql_get_result($db);
//    echo microtime(true) - $s, "\n";
//    //var_dump($r);
//    exit(0);
//});

$db->query($sql2, MYSQLI_ASYNC);
swoole_event_add(swoole_get_mysqli_sock($db), function($__db_sock) {
    global $db;
    $s = microtime(true);
    $res = $db->reap_async_query();
    $r = $res->fetch_all();
    echo microtime(true) - $s, "\n";
    //var_dump($r, $db->affected_rows, $db->insert_id);
    exit(0);
});