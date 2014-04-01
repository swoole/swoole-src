<?php
swoole_async_dns_lookup("www.baidu.com", function($host, $ip){
	echo "{$host} reslove to {$ip}\n";
	swoole_event_exit();
});
