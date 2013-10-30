<?php
$db = new mysqli;
$db->connect('127.0.0.1', 'root', 'root', 'test');

$db->query("show databases", MYSQLI_ASYNC);
sleep(1);
if ($result = $db->reap_async_query()) 
{
    print_r($result->fetch_row());
    if(is_object($result))
    {
		mysqli_free_result($result);
	}
}
else die(sprintf("MySQLi Error: %s", mysqli_error($link)));

$db->query("show tables", MYSQLI_ASYNC);
sleep(1);
if ($result = $db->reap_async_query()) 
{
    print_r($result->fetch_row());
    if(is_object($result))
    {
		mysqli_free_result($result);
	}
}
else die(sprintf("MySQLi Error: %s", mysqli_error($link)));
