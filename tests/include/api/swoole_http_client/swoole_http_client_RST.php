<?php

require_once __DIR__ . "/../../../include/bootstrap.php";


// 旧版本一个bug, 连接收到RST会coredump

// 1. 对端发送RST
// 2. 对端不回任何segment
function test_connect_refused()
{
    static $clients = [];
    $hosts = ["115.239.211.112", "127.0.0.1", "11.11.11.11"];

    for ($i = 0; $i < 2000; $i++) {
        $host = $hosts[$i % 3];
        $port = 8000 + $i;
        echo "get $host:$port\n";
        $cli = new swoole_http_client($host, $port);
        $cli->setHeaders(["Connection" => "close"]);
        $cli->get("/", function(swoole_http_client $cli) {
            echo "receive:", $cli->body, "\n";
        });
        swoole_timer_after(3000, function() use($cli, &$clients) {
            $cli->close();
            unset($clients[spl_object_hash($cli)]);
        });

        $clients[spl_object_hash($cli)] = $cli; // 防止swoole 引用计数处理错误
    }
}

test_connect_refused();
