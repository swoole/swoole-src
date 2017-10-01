<?php

require_once __DIR__ . "/../../../include/bootstrap.php";


/*
class swoole_http_client
{
 public swoole_function __construct() {}
 public swoole_function __destruct() {}
 public swoole_function set() {}
 public swoole_function setMethod() {}
 public swoole_function setHeaders() {}
 public swoole_function setCookies() {}
 public swoole_function setData() {}
 public swoole_function execute() {}
 public swoole_function push() {}
 public swoole_function get() {}
 public swoole_function post() {}
 public swoole_function isConnected() {}
 public swoole_function close() {}
 public swoole_function on() {}
}
*/


function addTimer(\swoole_http_client $httpClient)
{
    if (property_exists($httpClient, "timeo_id")) {
        return false;
    }
    return $httpClient->timeo_id = swoole_timer_after(1000, function() use($httpClient) {
        debug_log("http request timeout");

        // TODO 超时强制关闭连接 server端: ERROR	swFactoryProcess_finish (ERROR 1005): session#%d does not exist.
        $httpClient->close();
        assert($httpClient->isConnected() === false);
    });
}

function cancelTimer($httpClient)
{
    if (property_exists($httpClient, "timeo_id")) {
        $ret = swoole_timer_clear($httpClient->timeo_id);
        unset($httpClient->timeo_id);
        return $ret;
    }
    return false;
}


function makeHttpClient($host = HTTP_SERVER_HOST, $port = HTTP_SERVER_PORT, $ssl = true)
{
    $httpClient = new \swoole_http_client($host, $port, $ssl);

    $httpClient->set([
        'timeout' => 1,
        "socket_buffer_size" => 1024 * 1024 * 2,
    ]);
    if ($ssl) {
        $httpClient->set([
            'ssl_cert_file' => __DIR__ . '/../swoole_http_server/localhost-ssl/server.crt',
            'ssl_key_file' => __DIR__ . '/../swoole_http_server/localhost-ssl/server.key',
        ]);
    }

    $httpClient->on("connect", function(\swoole_http_client $httpClient) {
        assert($httpClient->isConnected() === true);
        // debug_log("connect");
    });

    $httpClient->on("error", function(\swoole_http_client $httpClient) {
        // debug_log("error");
    });

    $httpClient->on("close", function(\swoole_http_client $httpClient) {
        // debug_log("close");
    });

    return $httpClient;
}

function testUri($host, $port, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port, true);

    addTimer($httpClient);
    $ok = $httpClient->get("/uri", function(\swoole_http_client $httpClient) use($fin) {
        cancelTimer($httpClient);
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        assert($httpClient->body === "/uri");
        if ($fin) {
            $fin($httpClient);
        }
    });
    assert($ok);
}

function testHttpsGet($host, $port, array $query, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port, true);

    $queryStr = http_build_query($query);
    $ok = $httpClient->get("/get?$queryStr", function(\swoole_http_client $httpClient) use($query, $fin, $queryStr) {
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        // $httpClient->headers;
        if ($queryStr === "") {
            assert($httpClient->body === "null");
        } else {
            $ret = json_decode($httpClient->body, true);
            assert(arrayEqual($ret, $query, false));
        }
        if ($fin) {
            $fin($httpClient);
        }
    });
    assert($ok);
}


function testPost($host, $port, array $query, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port, true);

    $ok = $httpClient->post("/post", $query, function(\swoole_http_client $httpClient) use($query, $fin) {
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        // $httpClient->headers;
        $ret = json_decode($httpClient->body, true);
        assert(arrayEqual($ret, $query, false));
        if ($fin) {
            $fin($httpClient);
        }
    });
    assert($ok);
}


function testMethod($host, $port, $method, $data = null, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port, true);

    addTimer($httpClient);
    $ok = $httpClient->setMethod($method);
    assert($ok);
    if ($data) {
        $httpClient->setData($data);
    }
    $ok = $httpClient->execute("/method", function(\swoole_http_client $httpClient) use($method, $fin) {
        cancelTimer($httpClient);
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        assert($httpClient->body === $method);
        if ($fin) {
            $fin($httpClient);
        }
    });
    assert($ok);
}

function testCookie($host, $port, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port, true);
    addTimer($httpClient);
    $ok = $httpClient->setCookies(["hello" => "world"]);
    assert($ok);

    $ok = $httpClient->get("/cookie", function(\swoole_http_client $httpClient) use($fin) {
        cancelTimer($httpClient);
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        assert($httpClient->body === "{\"hello\":\"world\"}");
        if ($fin) {
            $fin($httpClient);
        }
    });
    assert($ok);
}

function testCookieCore($host, $port, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port, true);
    addTimer($httpClient);
    $ok = $httpClient->setCookies("hello=world; path=/;");
    assert($ok);

    $ok = $httpClient->get("/cookie", function(\swoole_http_client $httpClient) use($fin) {
        cancelTimer($httpClient);
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        var_dump($httpClient->body);
        if ($fin) {
            $fin($httpClient);
        }
    });
    assert($ok);
}

function testHeader($host, $port, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port, true);
    addTimer($httpClient);

    $httpClient->setting += ["keep_alive" => true];
    // TODO 只要调用setHeaders 则会变为 connection close
    $ok = $httpClient->setHeaders(["hello" => "world"]);
    assert($ok);

    $ok = $httpClient->get("/header", function(\swoole_http_client $httpClient) use($fin) {
        cancelTimer($httpClient);
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        $headers = json_decode($httpClient->body, true);
        assert(isset($headers["hello"]) && $headers["hello"] === "world");
        if ($fin) {
            $fin($httpClient);
        }
    });
    assert($ok);
}

// 已经修复
function testHttpsHeaderCore($host, $port, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port, true);
    // $httpClient->setting += ["keep_alive" => true];
    // COREDUMP
    // 旧版传递字符串会发生coredump
    // $httpClient->setHeaders("Hello: World\r\nHello: World\r\n");
    $r = $httpClient->setHeaders(["\0" => "\0"]);

    $ok = $httpClient->get("/header", function(\swoole_http_client $httpClient) use($fin) {
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        $headers = json_decode($httpClient->body, true);
        if ($fin) {
            $fin($httpClient);
        }
    });
    assert($ok);
}

function testSleep($host, $port)
{
    $httpClient = makeHttpClient($host, $port, true);
    addTimer($httpClient);

    $ok = $httpClient->get("/sleep", function(\swoole_http_client $httpClient) {
        assert(false);
    });
    assert($ok);
}


function request($host, $port, $method, $url, $body, array $header, array $cookie, callable $finish)
{
    $httpClient = makeHttpClient($host, $port, true);
    addTimer($httpClient);
    $httpClient->setMethod($method);

    if ($cookie) {
        $httpClient->setCookies($cookie);
    }
    if ($header) {
        $httpClient->setCookies($header);
    }

    if ($body) {
        $httpClient->setData($body);
    }

    $httpClient->setting += ["keep_alive" => false];
    $httpClient->execute($url, function(\swoole_http_client $httpClient) use($finish) {
        cancelTimer($httpClient);
        $finish($httpClient);
        $httpClient->close();
    });
}