--TEST--
swoole_http_client: content length

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/swoole_http_client/simple_http_client.php';

$simple_http_server = __DIR__ . "/../include/api/swoole_http_server/simple_http_server.php";
$closeServer = start_server($simple_http_server, HTTP_SERVER_HOST, $port = get_one_free_port());

$makeDone = function($n, $f) {
    return function() use(&$n, $f) {
        $n--;
        if ($n === 0) {
            $f();
        }
    };
};
$done = $makeDone(2, $closeServer);

$data = ['value' => RandStr::gen(rand(0, 1024))];
testExecute(HTTP_SERVER_HOST, $port, null, $data, function ($httpClient) use ($data, $done)
{
    echo "SUCCESS\n";
    $done();
});

testExecute(HTTP_SERVER_HOST, $port, "POST", $data, function ($httpClient) use ($data, $done)
{
    echo "SUCCESS\n";
    $done();
});
?>
--EXPECT--
SUCCESS
SUCCESS