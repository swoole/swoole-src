<?php

`pkill php-fpm`;
require __DIR__ . "/../../../include/bootstrap.php";
require_once __DIR__ . "/simple_http_client.php";

$host = HTTP_SERVER_HOST;
$port = HTTP_SERVER_PORT;


$data = null;
testExecute($host, $port, null, $data, function($httpClient) use($data) {
    assert(0 === intval($httpClient->body));
    echo "SUCCESS";
});


$data = null;
testExecute($host, $port, "POST", $data, function($httpClient) use($data) {
    assert(0 === intval($httpClient->body));
    echo "SUCCESS";
});


$data = RandStr::gen(rand(0, 1024));
testExecute($host, $port, "POST", $data, function($httpClient) use($data) {
    assert(strlen($data) === intval($httpClient->body));
    echo "SUCCESS";
});

exit;



testHttpsHeaderCore($host, $port);
testUri($host, $port);

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
// testCookieCore($host, $port);

testHttpsHeaderCore($host, $port);
testHeader($host, $port);

testSleep($host, $port);



//request($host, $port, "GET", "/", null,
//    ["cookie_key" => "cookie_value"],
//    ["header_key" => "header_value"],
//    swoole_function(swoole_http_client $cli) {
//        assert($cli->body === "Hello World!");
//    });
