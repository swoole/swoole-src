<?php
$db = new mysqli;
$db->connect('127.0.0.1', 'root', 'root', 'test');
var_dump($db->get_charset());
$r = $db->escape_string("abc'efg\r\n");

var_dump($r);

//$res = $db->query("show databases");

