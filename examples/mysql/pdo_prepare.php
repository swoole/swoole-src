<?php
$db = new PDO("dbtype:host=127.0.0.1;dbname=test;charset=utf8", "root" ,"root");
$query=$db->prepare("Select * from table where id=?");
$query->excute(array($myinsecuredata));
