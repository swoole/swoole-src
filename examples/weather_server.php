<?php
error_reporting(E_ALL);
ini_set('display_errors', '1');
ini_set('memory_limit', '-1');

class HttpServ
{
    public $http;
    public $setting = array();

    public function __construct()
    {

    }

    public function set($setting)
    {
        $this->setting = $setting;
    }

    public function init()
    {

        $this->http = new swoole_http_server($this->setting['host'], $this->setting['port'], SWOOLE_BASE);
        $this->http->set($this->setting);
        //register_shutdown_function('handleFatal');
        $this->http->on('request', function ($request, $response)
        {
            if ($request->server['request_uri'] == '/favicon.ico')
            {
                $response->status(404);
                $response->end('Not Found');
                return;
            }
            $this->getResult($response);
        });
    }

    function getResult2($response)
    {
        $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
        $client->on('connect', function ($cli)
        {
            echo "cli1 connect\n";
            $cli->send("hello world\n");
        });

        $client->on('Receive', function ($cli, $data) use ($response)
        {
            echo "cli1 receive\n";
            $response->end($data);
            $cli->close();
        });

        $client->on("error", function ($cli)  use ($response)
        {
            echo "cli1 error\n";
            $response->end("empty\n");
        });

        $client->on("close", function ($cli)
        {
            echo "cli1 close\n";
        });
        $client->connect('127.0.0.1', 9501);
    }

    function getResult5($response)
    {
        swoole_async_dns_lookup("weather.gtimg.cn", function ($host, $ip) use ($response)
        {
            $response->header('Content-Type', 'application/json');
            $response->write(json_encode(array($host => $ip)));
            $response->end();
        });
    }

    function getResult3($response)
    {
        $cityId = '01010101';
//        swoole_async_dns_lookup("weather.gtimg.cn", function ($host, $ip) use ($cityId, $response)
//        {
//            if (empty($ip))
//            {
//                return $ret;
//            }
//            else
//            {
                $ip = '14.18.245.236';
                $httpcli = new swoole_http_client($ip, 80);
                //$httpcli->on("close", function($httpcli){});
                $url = "/qqindex/" . $cityId . ".js?_ref=14";

                $httpcli->get($url, function ($hcli) use ($response)
                {
                    //echo "get content is" . $hcli->body;
                    $retWeather = iconv("GBK", 'UTF-8', $hcli->body);
                    //echo "ret:" . $retWeather;
                    $hcli->close();

                    $response->header('Content-Type', 'application/json');
                    $response->write(json_encode($retWeather));
                    $response->end();
                });
//            }
//        });
    }

    function getResult($response)
    {
        $client = new swoole_redis();
        $ip = "127.0.0.1";
        $port = 6379;

        $client->connect($ip, $port, function (swoole_redis $client, $result) use ($response)
        {
            if ($result === false)
            {
                echo "connect to redis server failed\n";
                return false;
            }
            $client->GET('test', function (swoole_redis $client, $result) use ($response)
            {
                //echo "get  result is :" . $result;
                $client->close();
                $cityId = '01010101';
                swoole_async_dns_lookup("weather.gtimg.cn", function ($host, $ip) use ($cityId, $response)
                {
                    if (empty($ip))
                    {
                        return false;
                    }
                    else
                    {
                        $httpcli = new swoole_http_client($ip, 80);
                        //$httpcli->on("close", function($httpcli){});
                        $url = "/qqindex/" . $cityId . ".js?_ref=14";

                        $httpcli->get($url, function ($hcli) use ($response)
                        {
                            //echo "get content is" . $hcli->body;
                            $retWeather = iconv("GBK", 'UTF-8', $hcli->body);
                            //echo "ret:" . $retWeather;
                            $hcli->close();

                            $response->header('Content-Type', 'application/json');
                            $response->write(json_encode($retWeather));
                            $response->end();

                        });
                    }
                });
            });
        });
    }

    function getResult4($response)
    {
        $client = new swoole_redis();
        $ip = "127.0.0.1";
        $port = 6379;

        $client->connect($ip, $port, function (swoole_redis $client, $result) use ($response)
        {
            if ($result === false)
            {
                echo "connect to redis server failed\n";
                return false;
            }
            $client->GET('key', function (swoole_redis $client, $result) use ($response)
            {
                //echo "get  result is :" . $result;
                $response->header('Content-Type', 'application/json');
                $response->end($result);
            });
        });
    }

    public function start()
    {
        $this->init();
        $this->http->start();
    }
}


$setting = array(

    'host' => '127.0.0.1',
    'port' => 9100,
    'worker_num' => 1,
    'dispatch_mode' => 2,
    //'reactor_num' => 4,
    'daemonize' => 0,
    //'log_file' => './logs/test_udp_server.log',
);


$server = new HttpServ();
$server->set($setting);
$server->start();
