<?php
$db = new mysqli('127.0.0.1', 'root', 'root', 'test');

$stmt = $db->prepare("SELECT id, name FROM userinfo WHERE id=?");
var_dump($stmt);
$id = 1;
$stmt->bind_param('i', $id);
$stmt->execute();

$stmt->bind_result($id, $name);
$stmt->fetch();

var_dump($id, $name);
$stmt->close();
