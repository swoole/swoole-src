<?php

require_once __DIR__ . "/../../../include/bootstrap.php";

class HttpServer
{
    /**
     * @var \swoole_http_server
     */
    public $httpServ;

    public function __construct($host = HTTP_SERVER_HOST, $port = HTTP_SERVER_PORT, $ssl = false)
    {
        if ($ssl) {
            $this->httpServ = new \swoole_http_server($host, $port, SWOOLE_PROCESS, SWOOLE_SOCK_TCP | SWOOLE_SSL);
        } else {
            $this->httpServ = new \swoole_http_server($host, $port, SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
        }

        $config = [
            // 输出限制
            "buffer_output_size" => 1024 * 1024 * 1024,
            "max_connection" => 10240,
            "pipe_buffer_size" => 1024 * 1024 * 1024,
            // 'enable_port_reuse' => true,
            'user' => 'www-data',
            'group' => 'www-data',
            'log_file' => '/tmp/swoole.log',
            'dispatch_mode' => 3,
            'open_tcp_nodelay' => 1,
            'open_cpu_affinity' => 1,
            'daemonize' => 0,
            'reactor_num' => 1,
            'worker_num' => 2,
            'max_request' => 100000,

            /*
            'package_max_length' => 1024 * 1024 * 2
            'open_length_check' => 1,
            'package_length_type' => 'N',
            'package_length_offset' => 0,
            'package_body_offset' => 0,
            'open_nova_protocol' => 1,
            */
        ];

        if ($ssl)
        {
            $config['ssl_cert_file'] = __DIR__ . '/localhost-ssl/server.crt';
            $config['ssl_key_file'] = __DIR__ . '/localhost-ssl/server.key';
        }
        $this->httpServ->set($config);
    }

    public function start()
    {
        $this->httpServ->on('start', [$this, 'onStart']);
        $this->httpServ->on('shutdown', [$this, 'onShutdown']);

        $this->httpServ->on('workerStart', [$this, 'onWorkerStart']);
        $this->httpServ->on('workerStop', [$this, 'onWorkerStop']);
        $this->httpServ->on('workerError', [$this, 'onWorkerError']);

        $this->httpServ->on('connect', [$this, 'onConnect']);
        $this->httpServ->on('receive', [$this, 'onReceive']);
        $this->httpServ->on('request', [$this, 'onRequest']);

        $this->httpServ->on('close', [$this, 'onClose']);

        $sock = $this->httpServ->getSocket();
        if (!socket_set_option($sock, SOL_SOCKET, SO_REUSEADDR, 1)) {
            echo 'Unable to set option on socket: '. socket_strerror(socket_last_error()) . PHP_EOL;
        }
        $this->httpServ->start();
    }

    public function onConnect()
    {
        debug_log("connecting ......");
    }

    public function onClose()
    {
        debug_log("closing .....");
    }

    public function onStart(\swoole_http_server $swooleServer)
    {
        debug_log("swoole_server starting .....");
    }

    public function onShutdown(\swoole_http_server $swooleServer)
    {
        debug_log("swoole_server shutdown .....");
    }

    public function onWorkerStart(\swoole_http_server $swooleServer, $workerId)
    {
        debug_log("worker #$workerId starting .....");
    }

    public function onWorkerStop(\swoole_http_server $swooleServer, $workerId)
    {
        debug_log("worker #$workerId stopping ....");
    }

    public function onWorkerError(\swoole_http_server $swooleServer, $workerId, $workerPid, $exitCode, $sigNo)
    {
        debug_log("worker error happening [workerId=$workerId, workerPid=$workerPid, exitCode=$exitCode, signalNo=$sigNo]...");
    }

    public function onReceive(\swoole_http_server $swooleServer, $fd, $fromId, $data)
    {
        $recv_len = strlen($data);
        debug_log("receive: len $recv_len");
        $swooleServer->send($fd, RandStr::gen($recv_len, RandStr::ALL));
    }

    public function onRequest(\swoole_http_request $request, \swoole_http_response $response)
    {
        $uri = $request->server["request_uri"];
        if ($uri === "/favicon.ico")  {
            $response->status(404);
            $response->end();
            return;
        }

        testSetCookie:
        {
            $name = "name";
            $value = "value";
            // $expire = $request->swoole_server["request_time"] + 3600;
            $expire = 0;
            $path = "/";
            $domain = "";
            $secure = false;
            $httpOnly = true;
            // string $name [, string $value = "" [, int $expire = 0 [, string $path = "" [, string $domain = "" [, bool $secure = false [, bool $httponly = false ]]]]]]
            $response->cookie($name, $value, $expire, $path, $domain, $secure, $httpOnly);
            $expect = "name=value; path=/; httponly";
            assert(in_array($expect, $response->cookie, true));
        }


        if ($uri === "/ping")  {
            $this->httpServ->send($request->fd, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong\r\n");
            return;
        }

        if ($uri === "/gzip")  {
            $level = 9;
            $response->gzip($level);
            $response->end(RandStr::gen(1024 * 1024 * 2, RandStr::ALL));
            return;
        }

        if ($uri === "/info") {
            ob_start();
            print("request_uri: {$uri}\n");
            print("request_method: {$request->server['request_method']}\n");

            if (property_exists($request, "get")) {
                print("get:" . var_export($request->get, true) . "\n");
            }
            if (property_exists($request, "post")) {
                print("post:" . var_export($request->post, true) . "\n");
            }
            if (property_exists($request, "cookie")) {
                print("cookie:" . var_export($request->cookie, true) . "\n");
            }
            if (property_exists($request, "header")) {
                print("header:" . var_export($request->header, true) . "\n");
            }

            $response->end(nl2br(ob_get_clean()));
            return;
        }



        if ($uri === "/uri") {
            $response->end($request->server['request_uri']);
            return;
        }

        if ($uri === "/method") {
            $response->end($request->server['request_method']);
            return;
        }

        if ($uri === "/get") {
            if (!empty($request->get)) {
                $response->end(json_encode($request->get));
            } else {
                $response->end("null");
            }
            return;
        }

        if ($uri === "/post") {
            if (property_exists($request, "post")) {
                $response->end(json_encode($request->post));
            } else {
                $response->end("{}");
            }
            return;
        }

        if ($uri === "/cookie") {
            if (property_exists($request, "cookie")) {
                $response->end(json_encode($request->cookie));
            } else {
                $response->end("{}");
            }
            return;
        }

        if ($uri === "/header") {
            if (property_exists($request, "header")) {
                $response->end(json_encode($request->header));
            } else {
                $response->end("{}");
            }
            return;
        }

        if ($uri === "/sleep") {
            swoole_timer_after(1000, function() use($response) {
                $response->end();
            });
            return;
        }

        if ($uri === "/404") {
            $response->status(404);
            $response->end();
            return;
        }

        if ($uri === "/302") {
            $response->header("Location", "http://www.swoole.com/");
            $response->status(302);
            $response->end();
            return;
        }

        if ($uri === "/code") {
            swoole_async_readfile(__FILE__, function($filename, $contents) use($response) {
                $response->end(highlight_string($contents, true));
            });
            return;
        }

        if ($uri === "/json") {
            $response->header("Content-Type", "application/json");
            $response->end(json_encode($request->server, JSON_PRETTY_PRINT));
            return;
        }

        if ($uri === "/chunked") {
            $write = function($str) use($request) { return $this->httpServ->send($request->fd, $str); };

            $write("HTTP/1.1 200 OK\r\n");
            $write("Content-Encoding: chunked\r\n");
            $write("Transfer-Encoding: chunked\r\n");
            $write("Content-Type: text/html\r\n");
            $write("Connection: keep-alive\r\n");
            $write("\r\n");

            // "0\r\n\r\n" finish
            $writeChunk = function($str = "") use($write) {
                $hexLen = dechex(strlen($str));
                return $write("$hexLen\r\n$str\r\n");
            };
            $timer = swoole_timer_tick(200, function() use(&$timer, $writeChunk) {
                static $i = 0;
                $str = RandStr::gen($i++ % 40 + 1, RandStr::CHINESE) . "<br>";
                if ($writeChunk($str) === false) {
                    swoole_timer_clear($timer);
                }
            });
            return;
        }

        if ($uri === "/content_length") {
            // $body = $request->rawcontent();
            if (property_exists($request, "header")) {
                if (isset($request->header['content-length'])) {
                    $response->end($request->header['content-length']);
                } else {
                    $response->end(0);
                }
                return;
            }
        }

        if ($uri === "/rawcontent") {
            $response->end($request->rawcontent());
            return;
        }

        if ($uri === "/file") {
            $response->header("Content-Type", "text");
            $response->header("Content-Disposition", "attachment; filename=\"test.php\"");
            // TODO 这里会超时
            $response->sendfile(__FILE__);
        }

        if ($uri === "/rawcookie") {
            $response->cookie($name, $value, $expire, $path, $domain, $secure, $httpOnly);
            $response->rawcookie("rawcontent", $request->rawcontent());
        }

        $response->end("Hello World!");
    }
}
