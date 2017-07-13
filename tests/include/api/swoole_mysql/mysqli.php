<?php

$pdo = new \PDO('swoole_mysql:dbname=db_koudaitong;host=127.0.0.1;port=3007', 'user_koudaitong', 'ocfLsVO7l2B3TMOPmpSX');

// 1
//$stmt = $pdo->prepare("select * from attachment where mp_id = :mp_id LIMIT 10");
//$stmt->bindValue(":mp_id", 1, \PDO::PARAM_INT);

// 2
$stmt = $pdo->prepare("select * from attachment where mp_id = ? LIMIT 10");
$stmt->bindValue(1, 1, \PDO::PARAM_INT);

$stmt->execute();
$r = $stmt->fetchAll(\PDO::FETCH_ASSOC);
var_dump($r);


$mysqli = new \mysqli();
$mysqli->connect('127.0.0.1', 'user_koudaitong', 'ocfLsVO7l2B3TMOPmpSX', 'db_koudaitong', '3007');

if ($mysqli->connect_errno) {
    printf("Connect failed: [errno=%d]%s\n", $mysqli->connect_errno, $mysqli->connect_error);
    exit();
}

$stmt = $mysqli->prepare("select * from attachment where mp_id = ? LIMIT 10");
if ($stmt) {
    $kdt_id = 1;
    $stmt->bind_param("i", $kdt_id);
    $stmt->execute();
    $stmt->bind_result($r);
    $stmt->fetch();

    var_dump($r);

    $stmt->close();
} else {
    printf("Prepare failed: [errno=%d]%s\n", $mysqli->errno, $mysqli->error);
}

$mysqli->close();





//require_once __DIR__ . "/swoole_mysql_init.php";

// sql syntax error
//$ret = $link->query("select");
//echo $link->error, "\n"; // You have an error in your SQL syntax; check the manual that corresponds to your MySQL swoole_server version for the right syntax to use near '' at line 1
//echo $link->errno; //1064
//exit;

// select
//$ret = $link->query("select 1, 1, 1");
// var_dump(mysqli_fetch_field($ret));
// var_dump(mysqli_fetch_assoc($ret));
// var_dump(mysqli_fetch_all($ret));
//exit;


// insert
//$ret = $link->query("insert into ad (`kdt_id`, `num`, `data`, `valid`, `created_time`, `update_time`) VALUES (99999, 1, 'data', 1, 0, 0)");
//var_dump($ret);
//var_dump($link->insert_id);
//exit;