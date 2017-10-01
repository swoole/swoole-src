<?php
require_once __DIR__ . "/../../../include/bootstrap.php";

function makeHttpClient($host = HTTP_SERVER_HOST, $port = HTTP_SERVER_PORT, $ssl = false, $output = false, callable $done = null)
{
    $httpClient = new \swoole_http_client($host, $port, $ssl);

    $httpClient->set([
        "socket_buffer_size" => 1024 * 1024 * 2,
        'timeout' => 1.0,
    ]);
    if ($ssl) {
        $httpClient->set([
            'ssl_cert_file' => __DIR__ . '../swoole_http_server/localhost-ssl/swoole_server.crt',
            'ssl_key_file' => __DIR__ . '../swoole_http_server/localhost-ssl/swoole_server.key',
        ]);
    }

    $httpClient->on("connect", function(\swoole_http_client $httpClient) {
        assert($httpClient->isConnected() === true);
        // debug_log("connect");
    });

    $httpClient->on("error", function(\swoole_http_client $httpClient) use($output, $done) {
        if ($output) {
            echo "error";
        }
        if ($done) {
            $done();
        }
        // debug_log("error");
    });

    $httpClient->on("close", function(\swoole_http_client $httpClient) use($output, $done) {
        if ($output) {
            echo "close";
        }
        if ($done) {
            $done();
        }
        // debug_log("close");
    });

    return $httpClient;
}

function testUri($host, $port, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);

    $ok = $httpClient->get("/uri", function(\swoole_http_client $httpClient) use($fin) {
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        assert($httpClient->body === "/uri");
        if ($fin) {
            $fin($httpClient);
        }
    });
    assert($ok);
}

function testHttpGet($host, $port, array $query, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);

    $queryStr = http_build_query($query);
    $ok = $httpClient->get("/get?$queryStr", function (\swoole_http_client $httpClient) use ($query, $fin, $queryStr)
    {
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        if ($queryStr === "")
        {
            assert($httpClient->body === "null");
        }
        else
        {
            $ret = json_decode($httpClient->body, true);
            assert(arrayEqual($ret, $query, false));
        }
        if ($fin)
        {
            $fin($httpClient);
        }
    });
    assert($ok);
}


function testPost($host, $port, array $query, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);

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
    $httpClient = makeHttpClient($host, $port);

    $ok = $httpClient->setMethod($method);
    assert($ok);
    if ($data) {
        $httpClient->setData($data);
    }
    $ok = $httpClient->execute("/method", function(\swoole_http_client $httpClient) use($method, $fin) {
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
    $httpClient = makeHttpClient($host, $port);
    $ok = $httpClient->setCookies(["hello" => "world"]);
    assert($ok);

    $ok = $httpClient->get("/cookie", function(\swoole_http_client $httpClient) use($fin) {
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        assert($httpClient->body === "{\"hello\":\"world\"}");
        if ($fin) {
            $fin($httpClient);
        }
    });
    assert($ok);
}

// setCookies 已经加入类型限制
function testCookieCore($host, $port, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);
    $ok = $httpClient->setCookies("hello=world; path=/;");
    assert($ok);

    $ok = $httpClient->get("/cookie", function(\swoole_http_client $httpClient) use($fin) {
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        assert($httpClient->body === "null");
        if ($fin) {
            $fin($httpClient);
        }
    });
    assert($ok);
}

function testHeader($host, $port, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);
    $httpClient->setting += ["keep_alive" => true];
    // TODO 只要调用setHeaders 则会变为 connection close
    $ok = $httpClient->setHeaders(["hello" => "world"]);
    assert($ok);

    $ok = $httpClient->get("/header", function(\swoole_http_client $httpClient) use($fin) {
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
function testHeaderCore($host, $port, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);

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
    $httpClient = makeHttpClient($host, $port);
    $ok = $httpClient->get("/sleep", function(\swoole_http_client $httpClient) {
        assert(false);
    });
    assert($ok);
}

// http message 分多次接受有问题 (10k message)
function testBigBodyMethodNotSupport($host, $port, callable $fin = null)
{
    if ($fin) {
        $httpClient = makeHttpClient($host, $port, false, true, $fin);
    } else {
        $httpClient = makeHttpClient($host, $port, false, true);
    }
    $body = str_repeat("\0", 10240);
    $ok = $httpClient->post("/", $body, function(\swoole_http_client $httpClient) use($fin) {
        echo "SUCCESS\n";
    });
    assert($ok);
}

// http message 分多次接受有问题 (间隔1s发送)
function testBigBodyMethodNotSupport2($host, $port, callable $fin = null)
{
    $cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

    $cli->on("connect", function(swoole_client $cli) {
        $cli->send("POST / HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: 1\r\n\r\n");
        swoole_timer_after(1, function() use($cli) {
            $cli->send("\0");
        });
    });

    $cli->on("receive", function(swoole_client $cli, $data){
        echo "SUCCESS";
    });

    $cli->on("error", function(swoole_client $cli) use($fin) {
        echo "error";
        if ($fin) {
            $fin();
        }
    });

    $cli->on("close", function(swoole_client $cli) use($fin) {
        echo "close";
        if ($fin) {
            $fin();
        }
    });

    $cli->connect($host, $port);
}

function testSendfile($host, $port, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);
    $httpClient->setMethod("GET");
    $ok = $httpClient->execute("/file", function(\swoole_http_client $httpClient) use($fin) {
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        if ($fin) {
            $fin($httpClient);
        }
    });
    assert($ok);
}

function testRawCookie($host, $port, $cookie, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);
    $httpClient->setMethod("POST");
    $httpClient->setData($cookie);
    $ok = $httpClient->execute("/rawcookie", function(\swoole_http_client $httpClient) use($fin) {
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        if ($fin) {
            $fin($httpClient);
        }
    });
    assert($ok);
}


function testRawcontent($host, $port, $data, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);
    if ($data !== false) {
        $httpClient->setData($data);
    }

    $httpClient->setMethod("POST");

    $ok = $httpClient->execute("/rawcontent", function(\swoole_http_client $httpClient) use($fin, $data) {
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        if ($fin) {
            $fin($httpClient);
        }
    });
    assert($ok);
}

function testExecute($host, $port, $method, $data, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);
    if ($data !== false) {
        $httpClient->setData($data);
    }

    if ($method) {
        $httpClient->setMethod("POST");
    }

    $ok = $httpClient->execute("/content_length", function(\swoole_http_client $httpClient) use($fin, $data) {
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        if ($fin) {
            $fin($httpClient);
        }
    });
    assert($ok);
}

function request($host, $port, $method, $url, $body, array $header, array $cookie, callable $finish)
{
    $httpClient = makeHttpClient($host, $port);
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
        $finish($httpClient);
        $httpClient->close();
    });
}
