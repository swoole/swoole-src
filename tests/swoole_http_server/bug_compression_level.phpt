--TEST--
swoole_http_server: bug http_compression_level not work
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_constant_not_defined('SWOOLE_HAVE_COMPRESSION');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const HTTP_GET_REQUEST = "GET / HTTP/1.1\r\nAccept-Encoding: gzip, deflate, br\r\n\r\n";
const MIN_COMPRESSION_LEVEL = 0;
const MAX_COMPRESSION_LEVEL = 9;

$randomBytes = str_repeat(get_safe_random(256), 1024);
$contentLengthArray = [];

for ($level = MIN_COMPRESSION_LEVEL; $level <= MAX_COMPRESSION_LEVEL; $level++) {
    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm) {
        Co\run(function () use ($pm) {
            $client = new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
            if (Assert::true($client->connect('127.0.0.1', $pm->getFreePort()))) {
                if (Assert::eq($client->sendAll(HTTP_GET_REQUEST), strlen(HTTP_GET_REQUEST))) {
                    $response = $client->recv();
                    if (Assert::greaterThan(preg_match('/Content-Length: (\d+)/', $response, $match), 0)) {
                        global $contentLengthArray;
                        $contentLengthArray[] = intval($match[1]);
                    }
                }
            }
            $client->close();
        });
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $level, $randomBytes) {
        phpt_var_dump($level);
        $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort());
        $http->set([
            'log_file' => '/dev/null',
            'http_compression' => true,
            'http_compression_level' => $level
        ]);
        $http->on('workerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($http, $randomBytes) {
            $response->end($randomBytes);
        });
        $http->start();
    };
    $pm->childFirst();
    $pm->run();
}
$sortedContentLengthArray = $contentLengthArray;
rsort($sortedContentLengthArray);
phpt_var_dump($contentLengthArray);
phpt_var_dump($sortedContentLengthArray);
if (!Assert::same($sortedContentLengthArray, $contentLengthArray)) {
    var_dump($contentLengthArray);
    var_dump($sortedContentLengthArray);
}
echo "DONE\n";

?>
--EXPECT--
DONE
