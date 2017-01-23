<?php
swoole_async_set(array(
    //使用纯异步IO
    'use_async_resolver' => true,
    'disable_dns_cache' => true,
    'dns_lookup_random' => true,
    'dns_server' => '114.114.114.114',
));
swoole_async_dns_lookup("www.sina.com.cn", function ($host, $ip)
{
    echo "{$host} reslove to {$ip}\n";
});

swoole_async_dns_lookup("www.baidu.com", function ($host, $ip)
{
    echo "{$host} reslove to {$ip}\n";
});
