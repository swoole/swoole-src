<?php
$db = new swoole_mysql;
$server = array(
    'host' => '127.0.0.1',
    'user' => 'chelun_appuser',
    'password' => 'hGbxB9PrmVLJzuxE',
    'database' => 'chelun',
);
$r = $db->connect($server, function ($db, $result)
{
    if ($result === false)
    {
        var_dump($db->connect_errno, $db->connect_error);
        die;
    }
    echo "connect to mysql server sucess\n";
    $sql = 'show tables';
    //$sql = "INSERT INTO `test`.`userinfo` (`id`, `name`, `passwd`, `regtime`, `lastlogin_ip`) VALUES (NULL, 'jack', 'xuyou', CURRENT_TIMESTAMP, '');";
    $db->query($sql, function (swoole_mysql $db, $r)
    {
        global $s;
        if ($r === false)
        {
            var_dump($db->error, $db->errno);
        }
        elseif ($r === true)
        {
            var_dump($db->affected_rows, $db->insert_id);
        }
        echo "count=" . count($r) . ", time=" . (microtime(true) - $s), "\n";
        //var_dump($r);
        $db->close();
    });
});

//$db->connect('10.10.2.205', 'root', '', 'msg_push', 3500);

//$sql =  "UPDATE  `test`.`userinfo` SET  `passwd` =  '999999' WHERE  `userinfo`.`id` =2";
//$sql = "INSERT INTO `test`.`userinfo` (`id`, `name`, `passwd`, `regtime`, `lastlogin_ip`) VALUES (NULL, 'jack', 'xuyou', CURRENT_TIMESTAMP, '');";
//$sql = "DELETE FROM `test`.`userinfo` WHERE `userinfo`.`id` = 59;";
//$sql = "SELECT * FROM  `userinfo` LIMIT 0, 100";
//$sql = "SELECT id,device_token,os from ec_push_token where 1 and app_key='QueryViolations' and os=2 and version >='5.0.0' and id > 0 limit 10000";
//$s = microtime(true);
//
//$db->query($sql, function(mysqli $db, $r) {
//    global $s;
//    if ($r == false)
//    {
//        var_dump($db->_error, $db->_errno);
//    }
//    elseif ($r == true )
//    {
//        var_dump($db->_affected_rows, $db->_insert_id);
//    }
//    echo "count=".count($r).", time=".(microtime(true) - $s), "\n";
//    var_dump($r);
////    swoole_mysql_query($db, "show tables", function ($db, $r) {
////	    var_dump($r);
////	});
//});

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
