<?php
$client = new swoole_client(SWOOLE_SOCK_TCP);
if(!$client->connect('127.0.0.1', 9501))
{
    exit("connect failed\n");
}
function help()
{
	echo "get eg: php ".__FILE__." get key".PHP_EOL;
	echo "set eg: php ".__FILE__." get key value".PHP_EOL;
	echo "det eg: php ".__FILE__." del key".PHP_EOL;
	exit();
}
if($argc < 3) {
	help();
}
$keys = array(
	1=>'cmd', 2=>'key', 3=>'val'
);
$sends = array();
foreach($keys as $i=>$key) {
	if(isset($argv[$i])) {
		$sends[$key] = $argv[$i];
	}
}
if(empty($sends)) {
	help();
}
$client->send(json_encode($sends));
$data = $client->recv();
var_dump($data);