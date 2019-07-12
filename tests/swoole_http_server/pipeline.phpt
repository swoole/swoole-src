--TEST--
swoole_http_server: http pipeline
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const N = 10;

$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {

    $client = new swoole_client(SWOOLE_SOCK_TCP);
    if (!$client->connect('127.0.0.1', $pm->getFreePort(), 1)) {
        exit("connect failed. Error: {$client->errCode}\n");
    }

    $host = 'localhost';
    foreach (range(1, N) as $_) {
        $get = http_build_query(['a' => str_repeat('A', rand(1024, 4096)), 'b' => 3.1415926]);
        $CR = "\r";
        $data = <<<HTTP
GET /?{$get} HTTP/1.1{$CR}
Host: {$host}{$CR}
Connection: closed{$CR}
Accept: */*{$CR}
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36{$CR}
{$CR}\n
HTTP;
        $client->send($data);
    }

    $html = '';
    while (1) {
        $data = $client->recv();
        if (!$data) {
            echo "ERROR\n";
            break;
        }
        $html .= $data;
        if (substr_count($html, "HTTP/1.1 200 OK") == N) {
            break;
        }
    }

    $pm->kill();
    Assert::same(substr_count($html, "HTTP/1.1 200 OK"), N);
    Assert::same(substr_count($html, "swoole-http-server"), N);
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['log_file' => '/dev/null']);
    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });
    $http->on("request", function (swoole_http_request $request, swoole_http_response $response) {
        $response->end(var_dump_return($request->get, $request->server));
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
