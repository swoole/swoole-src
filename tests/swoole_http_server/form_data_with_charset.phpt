--TEST--
swoole_http_server: http server parse form data with charset
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

define('EOF', get_safe_random());

function getRandomData(int $num): array
{
    $data = [];
    foreach (range(1, $num) as $_) {
        $key = substr(get_safe_random(32), 0, mt_rand(1, 32));
        $value = substr(get_safe_random(64), 0, mt_rand(0, 64));
        $data[$key] = $value;
    }

    return $data;
}

function arrayToMultipartString(array $var, string $boundary): string
{
    $ret = '';
    foreach ($var as $name => $value) {
        $value = (string)($value);
        $ret .= "--{$boundary}\r\nContent-Disposition: form-data; name=\"{$name}\"\r\n\r\n{$value}\r\n";
    }
    $ret .= "--{$boundary}--\r\n";

    return $ret;
}

function sendData(string $host, int $port, array $get, array $post): string
{
    $client = new Co\Client(SWOOLE_SOCK_TCP);
    if (!$client->connect($host, $port, 1)) {
        exit("connect failed. Error: {$client->errCode}\n");
    }

    $get = http_build_query($get);
    $boundary = '++++' . md5(get_safe_random(16));
    $content_type = "multipart/form-data; boundary={$boundary}; charset=UTF-8";
    $post = arrayToMultipartString($post, $boundary);

    $content_length = strlen($post);
    $CR = "\r";
    $data = <<<HTTP
POST /?{$get} HTTP/1.1{$CR}
Host: {$host}{$CR}
Connection: closed{$CR}
Accept: */*{$CR}
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36{$CR}
Content-Type: {$content_type}{$CR}
Content-Length: {$content_length}{$CR}
{$CR}
{$post}
HTTP;

    Assert::assert($client->send($data));
    $data = '';
    while ($ret = $client->recv()) {
        $data .= $ret;
        if (strrpos($data, EOF) !== false) {
            $data = substr($data, 0, strlen($data) - strlen(EOF));
            break;
        }
    }
    return $data;
}

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        foreach (range(1, 100) as $_) {
            $get = getRandomData(50);
            $post = getRandomData(100);
            $ret = sendData('127.0.0.1', $pm->getFreePort(), $get, $post);
            list($_, $body) = explode("\r\n\r\n", $ret);
            Assert::same($body, var_dump_return($get, $post));
        }
        $pm->kill();
        echo "DONE\n";
    });
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['log_file' => '/dev/null']);
    $http->on('WorkerStart', function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on('Request', function (swoole_http_request $request, swoole_http_response $response) use ($http) {
        $response->end(var_dump_return($request->get, $request->post));
        $http->send($request->fd, EOF);
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
