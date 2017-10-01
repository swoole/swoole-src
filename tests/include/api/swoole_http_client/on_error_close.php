<?php

require_once __DIR__ . "/../../../include/bootstrap.php";

// 旧版本因为没有做判断, 构造失败之后, 之后调用close会core

function error_close_test($desc, $ip, $port)
{
    $cli = new swoole_http_client($ip, $port);
    $cli->on("error", function() use($desc) { echo "$desc error\n"; });
    $cli->on("close", function() use($desc) { echo "$desc close\n"; });
    $cli->get("/", function($cli){ });
    swoole_timer_after(1000, function() use($cli) { $cli->close(); });
}

// 触发close 回调
error_close_test("baidu", "115.239.211.112", 80);

// 触发error回调
error_close_test("localhost", "127.0.0.1", 9090);

// TODO 此处行为不正确
// 应该校验参数是否合法ip, 抛出异常(构造函数无法返回错误)
error_close_test("\\0", "\0", 9090);

// TODO 同上
error_close_test("", "null string", 9090);