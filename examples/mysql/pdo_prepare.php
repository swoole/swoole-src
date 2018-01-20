<?php
$db = new PDO("mysql:host=127.0.0.1;dbname=test;charset=utf8", "root" ,"root");
$query = $db->prepare("select * from userinfo where id=?");
$rs = $query->execute(array(1));
var_dump($rs);
echo count($query->fetchAll());
