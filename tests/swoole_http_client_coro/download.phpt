--TEST--
swoole_http_client_coro: download file and download offset
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_travis('travis network');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$count = 0;
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm, &$count) {
    $raw_file_size = filesize(TEST_IMAGE);
    $raw_file_content = file_get_contents(TEST_IMAGE);
    for ($c = MAX_CONCURRENCY_LOW; $c--;) {
        go(function () use ($pm, &$count, $c, $raw_file_size, $raw_file_content) {
            $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            $cli->set(['timeout' => 5]);
            $filename = '/tmp/test-' . $c . '.jpg';
            $offset = mt_rand(0, $raw_file_size);
            $cli->setHeaders(['Range' => "bytes=$offset-"]);
            Assert::assert($cli->download('/', $filename, 0));
            // assert length
            if (!Assert::assert($raw_file_size === ($offset + filesize($filename)))) {
                goto _end;
            }
            // read content
            $raw_file = fopen(TEST_IMAGE, 'r+');
            fseek($raw_file, $offset);
            if (!Assert::assert(co::fread($raw_file) === co::readFile($filename))) {
                goto _end;
            }

            $count++;
            _end:
            @unlink($filename);
            $cli->setHeaders([]);
            $cli->get('/');
            Assert::same($cli->body, $raw_file_content);
        });
    }
    swoole_event_wait();
    Assert::same($count, MAX_CONCURRENCY_LOW);
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set(['log_file' => '/dev/null']);
    $serv->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $offset = (int) @explode('-', explode('=', $request->header['range'])[1])[0];
        $response->sendfile(TEST_IMAGE, $offset);
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
