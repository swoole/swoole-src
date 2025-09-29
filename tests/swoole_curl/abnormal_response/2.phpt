--TEST--
swoole_curl/abnormal_response: 2
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Server;
use Swoole\Runtime;

use function Swoole\Coroutine\run;
$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function () use ($pm) {
    Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    run(function () use ($pm) {
        $ch = curl_init();
        $code = uniqid('swoole_');
        $url = "http://127.0.0.1:" . $pm->getFreePort() . "/?code=" . urlencode($code);

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        $output = curl_exec($ch);
        Assert::isEmpty($output);
        Assert::eq(curl_errno($ch), CURLE_PARTIAL_FILE);
        curl_close($ch);
    });
    $pm->kill();
    echo "Done\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Server("127.0.0.1", $pm->getFreePort());
    $server->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $server->on("start", function ($server) use ($pm) {
        $pm->wakeup();
    });
    $server->on('Receive', function ($serv, $fd, $wid, $data) {
        usleep(100);
        $serv->send($fd, "HTTP/1.1 200 OK\r\n" .
            "Content-Type: text/html; charset=UTF-8\r\n" .
            "Content-Length: 1256\r\n");
        usleep(10000);
        $serv->close($fd);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
Done
