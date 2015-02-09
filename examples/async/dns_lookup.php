<?php
for($i=0; $i < 100; $i++) {
    swoole_async_dns_lookup("www.baidu$i.com", function($host, $ip){
        echo "{$host} reslove to {$ip}\n";
    });
}
