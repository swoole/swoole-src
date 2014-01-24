<?php
if(!function_exists('swoole_get_mysqli_sock')) {
	die("no async_mysql support\n");
}
$db = new mysqli;
$db->connect('127.0.0.1', 'root', 'root', 'test');
$db->query("show tables", MYSQLI_ASYNC);
swoole_event_add(swoole_get_mysqli_sock($db), function($db_sock) {
    global $db;
    $res = $db->reap_async_query();
    var_dump($res->fetch_all(MYSQLI_ASSOC));
    swoole_event_exit();
});
echo "Finish\n";