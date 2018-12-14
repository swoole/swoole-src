--TEST--
swoole_http_client: download file
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    $cli = new swoole_http_client('127.0.0.1', $pm->getFreePort());
    $cli->on('close', function ($cli)
    {
        echo "close\n";
    });
    $cli->on('error', function ($cli)
    {
        echo "error\n";
    });
    $cli->download('/get_file', __DIR__.'/tmpfile', function ($cli)
    {
        assert($cli->statusCode == 200);
        assert(md5_file($cli->downloadFile) == md5_file(TEST_IMAGE));
        unlink(__DIR__ . '/tmpfile');
        $cli->get('/get?foo=bar', function ($cli) {
            echo "{$cli->body}\n";
            $cli->close();
        });
    });
    swoole_event::wait();
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    include __DIR__ . "/../include/api/http_server.php";
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
{"foo":"bar"}
close
