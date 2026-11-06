--TEST--
swoole_http_server: 100-continue
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('curl_init');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const CONTINUE_RESPONSE = "HTTP/1.1 100 Continue\r\n\r\n";

function connectHttpServer(ProcessManager $pm): Swoole\Coroutine\Socket
{
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::true($socket->connect('127.0.0.1', $pm->getFreePort()));
    return $socket;
}

function recvContinue(Swoole\Coroutine\Socket $socket): string
{
    $response = $socket->recv();
    Assert::same($response, CONTINUE_RESPONSE);
    return $response;
}

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:{$pm->getFreePort()}");
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Expect: 100-continue']);

    $file = TEST_IMAGE;
    $post_data = array('test' => str_repeat('a', 80));
    if (function_exists("curl_file_create")) {
        $cfile = curl_file_create($file);
        $post_data['file'] = $cfile;
    } else {
        $post_data['file'] = '@' . $file;
    }

    curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);  //POST数据
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $res = curl_exec($ch);
    Assert::assert(!empty($res));
    Assert::same($res, md5_file($file));
    curl_close($ch);

    Swoole\Coroutine\run(function () use ($pm) {
        $socket = connectHttpServer($pm);
        $request =
            "POST /length HTTP/1.1\r\n" .
            "Host: localhost\r\n" .
            "Content-Length: 10\r\n" .
            "Expect: 100-continue\r\n\r\n";
        Assert::same($socket->sendAll($request), strlen($request));
        $response = recvContinue($socket);

        Assert::same($socket->sendAll('hello'), 5);
        usleep(1000);
        Assert::same($socket->sendAll('world'), 5);
        while (!str_contains($response, 'helloworld')) {
            $data = $socket->recv();
            Assert::assert($data !== false && $data !== '');
            $response .= $data;
        }
        Assert::same(substr_count($response, CONTINUE_RESPONSE), 1);

        $socket = connectHttpServer($pm);
        $request =
            "POST /chunked HTTP/1.1\r\n" .
            "Host: localhost\r\n" .
            "Transfer-Encoding: chunked\r\n" .
            "Expect: 100-continue\r\n\r\n";
        Assert::same($socket->sendAll($request), strlen($request));
        recvContinue($socket);

        $socket = connectHttpServer($pm);
        $request =
            "POST /multipart HTTP/1.1\r\n" .
            "Host: localhost\r\n" .
            "Content-Type: multipart/form-data; boundary=boundary\r\n" .
            "Content-Length: " . (2 * 1024 * 1024) . "\r\n" .
            "Expect: 100-continue\r\n\r\n";
        Assert::same($socket->sendAll($request), strlen($request));
        recvContinue($socket);
    });

    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);

    $http->set([
        'log_file' => '/dev/null',
        'upload_max_filesize' => 1024 * 1024,
    ]);

    $http->on("WorkerStart", function () use ($pm) {
        $pm->wakeup();
    });

    $http->on("request", function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        if ($request->server['request_uri'] === '/length') {
            $response->end($request->rawContent());
        } else {
            $response->end(md5_file($request->files['file']['tmp_name']));
        }
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
