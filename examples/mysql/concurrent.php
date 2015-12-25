<?php
define('CO_NUM', 20);
$sql = "SELECT id,device_token,os,create_time,app_key from ec_push_token where 1 and app_key='QueryViolations' and os=2 and version >='5.0.0'";
$all_count = 200000;
$page_size = 10000;
$sqls = $db_pool = array();
$start_time = microtime(1);

if ($all_count < $page_size)
{
    $count_chunk[] = 0;
    $count_chunk[] = $page_size;
}
else
{
    $count_chunk = range(0, $all_count, $page_size);
}
$array_chunk = array_chunk($count_chunk, 20);
foreach ($array_chunk as $chunks)
{
    foreach ($chunks as $k => $offset)
    {
        $sqls[$k][] = $sql . " limit $offset, $page_size";
    }
}

for ($i = 0; $i < CO_NUM; $i++)
{
    $db = new mysqli;
    $db->connect('10.10.2.91', 'root', '', 'msg_push', 3500);
    $db->_id = $i;
    $db_pool[] = $db;
}

for ($i = 0; $i < CO_NUM; $i++)
{
    $_sql = array_pop($sqls[$i]);
    swoole_mysql_query($db_pool[$i], $_sql, 'async_callback');
}

function async_callback($db, $result)
{
    global $sqls, $start_time;
    echo "RESULT: " . count($result) . "rows\n";

    if (count($sqls[$db->_id]) > 0)
    {
        $sql = array_pop($sqls[$db->_id]);
        swoole_mysql_query($db, $sql, 'async_callback');
    }
    else
    {
        unset($sqls[$db->_id]);
        echo "---------------------------------#{$db->_id} finish--------------------------------\n";
    }

    //全部完成
    if (count($sqls) == 0)
    {
        echo "time=" . (microtime(true) - $start_time) . "\n";
    }
}
