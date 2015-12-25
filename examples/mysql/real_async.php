<?php
if (!function_exists('swoole_get_mysqli_sock'))
{
    die("no async_mysql support\n");
}
$db = new mysqli;
//$db->connect('127.0.0.1', 'root', 'root', 'test');
$db->connect('10.10.2.205', 'root', '', 'msg_push', 3500);
//$sql1 =  "UPDATE  `test`.`userinfo` SET  `passwd` =  '888888' WHERE  `userinfo`.`id` =2";
//$sql2 = "INSERT INTO `test`.`userinfo` (`id`, `name`, `passwd`, `regtime`, `lastlogin_ip`) VALUES (NULL, 'jack', 'xuyou', CURRENT_TIMESTAMP, '');";
//$sql2 = "DELETE FROM `test`.`userinfo` WHERE `userinfo`.`id` = 23;";
//$sql2 = "SELECT * FROM  `userinfo` LIMIT 0, 100";
$sql = "SELECT id,device_token,os from ec_push_token where 1 and app_key='QueryViolations' and os=2 and version >='5.0.0' and id > 0 limit 10000";
$s = microtime(true);

swoole_mysql_query($db, $sql, function($mysqli, $r) {
    global $s;
    echo "count=".count($r).", time=".(microtime(true) - $s), "\n";
    //var_dump($r);
    exit(0);
});
//
//$db->query($sql, MYSQLI_ASYNC);
//swoole_event_add(swoole_get_mysqli_sock($db), function($__db_sock) {
//    global $db;
//    $s = microtime(true);
//    $res = $db->reap_async_query();
//    $r = $res->fetch_all();
//    echo "count=".count($r).", time=".(microtime(true) - $s), "\n";
//    exit(0);
//});