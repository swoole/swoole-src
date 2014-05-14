<?php
swoole_async_dns_lookup("www.baidu阿斯顿.com", function($host, $ip){
	echo "{$host} reslove to {$ip}\n";
	swoole_event_exit();
});
