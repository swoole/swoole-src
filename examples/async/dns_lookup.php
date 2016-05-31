<?php
swoole_async_dns_lookup("www.sina.com.cn", function($host, $ip){
    echo "{$host} reslove to {$ip}\n";
    swoole_async_dns_lookup("www.sina.com.cn", function($host, $ip){
        echo "{$host} reslove to {$ip}\n";
    });
});
