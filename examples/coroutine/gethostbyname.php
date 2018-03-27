<?php
use Swoole\Coroutine as co;

co::create(function() {
    $ip = co::gethostbyname("www.baidu.com");
    echo "IP: $ip\n";
});

