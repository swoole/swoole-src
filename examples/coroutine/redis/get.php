<?php
go(function (){
	$redis = new CO\Redis;
	var_dump($redis->connect("127.0.0.1", 6379));
	var_dump($redis->get("key"));
	var_dump($redis->set("key_22", str_repeat('A', 8192*256)));
	var_dump($redis->mget(["key", "key_22"]));
});
