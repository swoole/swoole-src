<?php
$db = new swoole_mysql;
$server = array(
    'host' => '127.0.0.1',
    'user' => 'root',
    'password' => 'root',
    'database' => 'test',
);

$db->on('close', function() use($db) {
    echo "mysql is closed.\n";
});

$r = $db->connect($server, function ($db, $result)
{
    echo "connect to mysql server sucess\n";
    if ($result === false)
    {
        var_dump($db->connect_errno, $db->connect_error);
        die;
    }
    $db->begin(function( $db, $result) {
        var_dump($result);
        $db->query("update userinfo set level = 22 where id = 1", function($db, $result) {
            var_dump($result, $db);
            $db->rollback(function($db, $result){
                echo "commit ok\n";
                var_dump($result, $db);
            });
        });
    });
});