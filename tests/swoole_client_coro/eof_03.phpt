--TEST--
swoole_client_coro: EOF framing with a local SMTP peer
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$greeting       = "220 smtp.test Esmtp Test Server\r\n";
$reply          = "250-smtp.test\r\n250-PIPELINING\r\n250-SIZE 73400320\r\n250-STARTTLS\r\n250-AUTH LOGIN PLAIN\r\n250-AUTH=LOGIN\r\n250-MAILCOMPRESS\r\n250 8BITMIME\r\n";
$pm             = new ProcessManager();
$pm->parentFunc = function () use ($pm, $greeting, $reply) {
    Co\run(function () use ($pm, $greeting, $reply) {
        $client = new Co\Client(SWOOLE_TCP);
        $client->set(['open_eof_check' => true, 'package_eof' => "\r\n"]);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 2));
        Assert::same($client->recv(2), $greeting);
        Assert::same($client->send("ehlo smtp.test\r\n"), strlen("ehlo smtp.test\r\n"));
        $received = '';
        while (strlen($received) < strlen($reply)) {
            $packet = $client->recv(2);
            Assert::notEmpty($packet);
            $received .= $packet;
        }
        Assert::same($received, $reply);
        $client->close();
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $greeting, $reply) {
    Co\run(function () use ($pm, $greeting, $reply) {
        $server = new Co\Socket(AF_INET, SOCK_STREAM, 0);
        Assert::true($server->bind('127.0.0.1', $pm->getFreePort()));
        Assert::true($server->listen());
        $pm->wakeup();
        $peer = $server->accept(2);
        Assert::isInstanceOf($peer, Co\Socket::class);
        Assert::same($peer->sendAll($greeting), strlen($greeting));
        Assert::same($peer->recvAll(strlen("ehlo smtp.test\r\n"), 2), "ehlo smtp.test\r\n");
        Assert::same($peer->sendAll($reply), strlen($reply));
        $peer->close();
        $server->close();
    });
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
