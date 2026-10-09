--TEST--
swoole_pdo_pgsql: connect timeout applies to each host
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Socket;

Co\run(static function (): void {
    $first = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($first->bind('127.0.0.1'));
    Assert::true($first->listen());
    // The second host accepts the TCP connection but never answers the startup packet.
    $second = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($second->bind('127.0.0.1'));
    Assert::true($second->listen());

    // The first host rejects the startup packet with "cannot connect now" after a delay, so libpq moves on.
    Co\go(static function () use ($first): void {
        $client = $first->accept();
        Assert::notEmpty($client->recv());
        Co::sleep(0.8);
        $fields = "SFATAL\0C57P03\0Mthe database system is starting up\0\0";
        $client->sendAll('E' . pack('N', strlen($fields) + 4) . $fields);
    });

    $dsn = sprintf(
        'pgsql:host=127.0.0.1,127.0.0.1;port=%d,%d;dbname=test;sslmode=disable',
        $first->getsockname()['port'],
        $second->getsockname()['port']
    );
    $start = microtime(true);
    try {
        new PDO($dsn, 'user', 'pass', [PDO::ATTR_TIMEOUT => 1]);
    } catch (PDOException $e) {
        Assert::eq($e->errorInfo[0], '08006');
        Assert::greaterThanEq(microtime(true) - $start, 1.8);
        echo "timeout\n";
    }
});
?>
--EXPECT--
timeout
