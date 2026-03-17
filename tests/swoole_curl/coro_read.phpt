--TEST--
swoole_curl: coroutine read
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;
use SwooleTest\ProcessManager;
use Swoole\Http\Request;
use Swoole\Http\Response;
use function Swoole\Coroutine\run;

$data = random_bytes(100 * 1024 * 1024);
file_put_contents('download.txt', $data);

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    run(function () use ($pm) {
        $fileHandle = fopen('download.txt', 'r');

        $url = $url = "http://127.0.0.1:" . $pm->getFreePort();
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_UPLOAD, true);
        curl_setopt($ch, CURLOPT_INFILE, $fileHandle);
        curl_setopt($ch, CURLOPT_INFILESIZE, filesize('download.txt'));
        $result = curl_exec($ch);
        curl_close($ch);
        fclose($fileHandle);
    });
    $pm->kill();
    echo "Done\n";
};

$pm->childFunc = function () use ($pm, $data) {
    $http = new Swoole\Http\Server("127.0.0.1", $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set(['worker_num' => 2, 'log_file' => '/dev/null', 'package_max_length' => 110 * 1024 * 1024]);

    $http->on("start", function ($server) use ($pm) {
        $pm->wakeup();
    });

    $http->on("request", function (Request $request, Response $response) use ($data) {
        var_dump($request->getContent() == $data);
        $response->end('Hello World');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
bool(true)
Done
--CLEAN--
<?php unlink('download.txt'); ?>
