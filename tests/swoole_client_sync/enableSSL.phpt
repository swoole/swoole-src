--TEST--
swoole_client_async: enableSSL
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$cli = new Swoole\Client(SWOOLE_SOCK_TCP);
Assert::true($cli->connect("www.baidu.com", 443, 2.0));

if ($cli->enableSSL()) {
    echo "SSL READY\n";
    $cli->send("GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\nUser-Agent: curl/7.50.1-DEV\r\nAccept: */*\r\n\r\n");
}

$resp = '';
while (true) {
    $data = $cli->recv();
    if ($data == false) {
        break;
    }
    $resp .= $data;
}

Assert::assert(strlen($resp) > 0);
Assert::contains($resp, 'www.baidu.com');
$cli->close();
echo "DONE\n";
?>
--EXPECT--
SSL READY
DONE
