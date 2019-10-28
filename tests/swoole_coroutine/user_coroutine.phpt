--TEST--
swoole_coroutine: user coroutine
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_travis('foreign network dns error');
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Coroutine\Http\Client as HttpClient;
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm)
{
    go(function () use ($pm) {
        $data= httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
        Assert::assert(strlen($data) > 1024);
        $pm->kill();
    });
    Swoole\Event::wait();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm)
{
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(array(
        'log_file' => '/dev/null'
    ));
    $http->on("WorkerStart", function (\swoole_server $serv)
    {
        /**
         * @var $pm ProcessManager
         */
        global $pm;
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response)
    {
        Swoole\Coroutine::create(function () use ($response)
        {
            $url = 'http://news.bitauto.com/xinche/';
            $components = parse_url($url);

            if (!isset($components['host']))
            {
                throw new \Exception("{$url} parse no host");
            }

            $host = $components['host'];

            $ip = swoole_async_dns_lookup_coro($host);
            $port = isset($components['port']) ? $components['port'] : 80;
            $client = new HttpClient($ip, $port);

            $client->setHeaders([
                'Host' => $host,
                'User-Agent' => 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:28.0) Gecko/20100101 Firefox/28.0',
            ]);
            $client->set(['timeout' => 10]);
            $client->get(isset($components['path']) ? $components['path'] : '/');
            $response->end($client->body);
        });
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
