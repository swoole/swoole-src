--TEST--
swoole_channel_coro: coroutine wait
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
        Assert::assert(!empty($data));
        $json = json_decode($data, true);
        Assert::assert(is_array($json));
        Assert::true(isset($json['www.qq.com']) and $json['www.qq.com'] > 1024);
        Assert::true(isset($json['www.163.com']) and $json['www.163.com'] > 1024);
        $pm->kill();
    });
    Swoole\Event::wait();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm)
{
    $serv = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->on("WorkerStart", function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('request', function ($req, $resp) {

        $chan = new chan(2);
        go(function () use ($chan) {
            $cli = new Swoole\Coroutine\Http\Client('www.qq.com', 443, true);
            $cli->set(['timeout' => 10]);
            $cli->setHeaders([
                'Host' => "www.qq.com",
                "User-Agent" => 'Chrome/49.0.2587.3',
                'Accept' => 'text/html,application/xhtml+xml,application/xml',
                'Accept-Encoding' => 'gzip',
            ]);
            $ret = $cli->get('/');
            if ($ret)
            {
                $chan->push(['www.qq.com' => strlen($cli->body)]);
            }
            else
            {
                $chan->push(['www.qq.com' => 0]);
            }
        });

        go(function () use ($chan) {
            $cli = new Swoole\Coroutine\Http\Client('www.163.com', 443, true);
            $cli->set(['timeout' => 10]);
            $cli->setHeaders([
                'Host' => "www.163.com",
                "User-Agent" => 'Chrome/49.0.2587.3',
                'Accept' => 'text/html,application/xhtml+xml,application/xml',
                'Accept-Encoding' => 'gzip',
            ]);
            $ret = $cli->get('/');
            if ($ret)
            {
                $chan->push(['www.163.com' => strlen($cli->body)]);
            }
            else
            {
                $chan->push(['www.163.com' => 0]);
            }
        });

        $result = [];
        for ($i = 0; $i < 2; $i++)
        {
            $result += $chan->pop();
        }
        $resp->end(json_encode($result));
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
