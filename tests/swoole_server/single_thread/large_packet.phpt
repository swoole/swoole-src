--TEST--
swoole_server/single_thread: large packet
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $url = 'http://127.0.0.1:' . $pm->getFreePort() . '/';
    $filePath = tempnam('/tmp', 'swoole_test_');
    $rdata = random_bytes(1024 * 1024);
    file_put_contents($filePath, $rdata);
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Accept: text/html',
        'Content-Type: multipart/form-data'
    ]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, [
        'file' => new CURLFile($filePath, 'text/html')
    ]);
    $response = curl_exec($ch);
    if (curl_errno($ch)) {
        echo 'ERROR: ' . curl_error($ch);
    } else {
        Assert::eq($response, md5($rdata));
    }
    curl_close($ch);
    unlink($filePath);
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('0.0.0.0', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set([
        'single_thread' => true,
        'worker_num' => 1,
        'dispatch_mode' => 10,
        'package_max_length' => '128m',
    ]);
    $http->on('WorkerStart', function (Swoole\Http\Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $http->on('Request', function ($request, $response) {
        $response->end(md5_file($request->files['file']['tmp_name']));
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
