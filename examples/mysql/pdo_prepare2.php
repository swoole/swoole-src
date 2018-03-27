<?php
$pdo = new PDO("mysql:host=127.0.0.1;dbname=test;charset=utf8", "root" ,"root");
$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);

$sql = "SELECT * FROM  userinfo WHERE `id`=:id";
$stmt = $pdo->prepare($sql); // 准备一条预处理语句

// 占位符的使用方法一, 这样还可以便面sql注入
$res = $stmt->execute(array(":id"=> 1)); 
if (!$res){
    echo exit("错误信息: ".var_dump($stmt->errorInfo()));
}
var_dump($stmt->rowCount());
var_dump($stmt->fetchAll());
