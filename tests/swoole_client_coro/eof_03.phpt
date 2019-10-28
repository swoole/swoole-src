--TEST--
swoole_client_coro: eof with smtp qq
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_travis();
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $client = new Co\Client(SWOOLE_TCP);
    $client->set([
        'open_eof_check' => true,
        'package_eof' => "\r\n",
    ]);
    $client->connect('smtp.qq.com', 25, 5);
    go(function () use ($client) {
        $n = 9;
        while ($n--) {
            $data = $client->recv();
            echo $data;
            if (empty($data)) {
                break;
            }
        }
    });
    $client->send("ehlo smtp.qq.com\r\n");
});
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
220 smtp.qq.com Esmtp QQ Mail Server
250-smtp.qq.com
250-PIPELINING
250-SIZE 73400320
250-STARTTLS
250-AUTH LOGIN PLAIN
250-AUTH=LOGIN
250-MAILCOMPRESS
250 8BITMIME
DONE
