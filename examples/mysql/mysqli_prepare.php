<?php
$db = new mysqli('127.0.0.1', 'root', 'root', 'test');

echo "connect success\n";

$stmt = $db->prepare("SELECT id, name FROM userinfo WHERE id=?");
//$stmt = $db->prepare("SELECT id, name FROM userinfo WHERE id=? and name=? and level=?");
//var_dump($stmt);
$id = 1;
//$name = 'jack';
//$level = 199;
exit;
$stmt->bind_param('i', $id);
//$stmt->bind_param('isi', $id, $name, $level);
echo "execute sql\n";
$stmt->execute();

$stmt->bind_result($id, $name);
$stmt->fetch();

var_dump($id, $name);
$stmt->close();

exit;
echo "prepare 2\n";

$stmt2 = $db->prepare("SELECT id, name FROM userinfo WHERE id=? and name=? and level=?");
var_dump($stmt2);
$id = 1;
$name = 'jack';
$level = 199;
$stmt2->bind_param('isi', $id, $name, $level);
echo "execute sql\n";
$stmt2->execute();

$stmt2->bind_result($id, $name);
$stmt2->fetch();

var_dump($id, $name);
//$stmt2->close();

