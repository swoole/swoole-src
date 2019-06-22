--TEST--
swoole_runtime/stream_select: never timeout
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
go(function () {
    $server1 = SwooleTest\CoServer::createHttpHelloWorld();
    $server1->run();
    $server2 = SwooleTest\CoServer::createHttpHelloWorld();
    $server2->run();
    $fp1 = stream_socket_client("tcp://127.0.0.1:{$server1->getPort()}", $errno, $errstr, 1);
    $fp2 = stream_socket_client("tcp://127.0.0.1:{$server2->getPort()}", $errno, $errstr, 1);
    if (Assert::resource($fp1)) {
        fwrite($fp1, "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\nUser-Agent: curl/7.58.0\r\nAccept: */*\r\n\r\n");
        $r_array = [$fp1, $fp2];
        $w_array = $e_array = null;
        $n = stream_select($r_array, $w_array, $e_array, null);
        Assert::assert($n == 1);
        Assert::assert(count($r_array) == 1);
        Assert::assert($r_array[0] == $fp1);
        $response = '';
        while (!feof($fp1)) {
            $response .= fgets($fp1);
        }
        Assert::contains($response, '200 OK');
        fclose($fp1);
    }
    $server1->shutdown();
    $server2->shutdown();
});
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
