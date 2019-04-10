--TEST--
swoole_http_client_coro: upload file with null args
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->addFile(TEST_IMAGE, 'test.jpg', null, null, 0, 0);
        $cli->post('/upload_file', ['name' => 'rango']);
        Assert::eq($cli->statusCode, 200);
        $ret = json_decode($cli->body, true);
        assert($ret and is_array($ret));
        Assert::eq($ret['files']['test_jpg']['name'], 'test.jpg');
        Assert::eq($ret['files']['test_jpg']['type'], 'image/jpeg');
        assert(preg_match('#/tmp/swoole\.upfile\.#', $ret['files']['test_jpg']['tmp_name']));
        Assert::eq($ret['files']['test_jpg']['error'], 0);
        Assert::eq($ret['files']['test_jpg']['size'], filesize(TEST_IMAGE));
        Assert::eq(md5_file(TEST_IMAGE), $ret['md5']);
        $cli->close();
    });
    swoole_event_wait();
    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    include __DIR__ . '/../include/api/http_server.php';
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
