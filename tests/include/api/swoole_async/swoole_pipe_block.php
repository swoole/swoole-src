<?php


require_once __DIR__ . "/../../../include/bootstrap.php";


function block_test($n = 20000)
{
    for ($i = 0; $i < $n; $i++) {
        $randStr = RandStr::gen(15);
        $host = "www.i_$randStr.com";

        swoole_async_dns_lookup($host, function($host, $ip) use($i) {
            echo "FIN i -> $ip\n";
        });
    }
}

block_test();
