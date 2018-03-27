--TEST--
swoole_coroutine: mysql query timeout
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/lib/curl.php";

go(function (){
    $mysql = new Swoole\Coroutine\MySQL();
    $res = $mysql->connect([
        'host' => MYSQL_SERVER_HOST,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ]);
    if (!$res)
    {
        fail : echo "CONNECT ERROR\n";

        return;
    }
    $ret = $mysql->query('select sleep(1)', 0.2);
    if (!$ret)
    {
        echo $mysql->errno ."\n";
        echo $mysql->error."\n";
    }
    else
    {
        var_dump($ret);
    }
});
swoole_event::wait();
?>
--EXPECT--
110
query timeout
