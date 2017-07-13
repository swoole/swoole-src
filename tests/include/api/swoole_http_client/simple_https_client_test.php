<?php

require_once __DIR__ . "/../../../include/bootstrap.php";
require_once __DIR__ . "/simple_https_client.php";


//request($host, $port, "GET", "/", null,
//    ["cookie_key" => "cookie_value"],
//    ["header_key" => "header_value"],
//    swoole_function(swoole_http_client $cli) {
//        assert($cli->body === "Hello World!");
//    });



testUri($host, $port);
testGet($host, $port, []);
testGet($host, $port, $_SERVER);
testPost($host, $port, $_SERVER);

testMethod($host, $port, "GET");
testMethod($host, $port, "DELETE");

testMethod($host, $port, "POST", "payload");
testMethod($host, $port, "PUT", "payload");
testMethod($host, $port, "PATCH", "payload");


// TODO bug, 没有校验
// testMethod($host, $port, "GET", "http_body");
// testMethod($host, $port, "DELETE", "http_body");
//testMethod($host, $port, "POST", null);
//testMethod($host, $port, "PUT", null);
//testMethod($host, $port, "PATCH", null);


testCookie($host, $port);
// TODO coredump
// testCookieCore();

testHttpsHeaderCore($host, $port);
testHeader($host, $port);

testSleep($host, $port);