<?php
$db = new swoole_mysql;
$db->connect('10.10.2.205', 'root', '', 'msg_push', 3500);
$db->query($sql, function(swoole_mysql $db, $r) {
    var_dump($r);
    $db->query("show tables", function(swoole_mysql $db, $r) {
        var_dump($r, $db->affected_rows, $db->insert_id);
    });
});

class swoole_mysql extends mysqli
{
    function query($sql, callable $callback){

    }
}