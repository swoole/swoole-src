--TEST--
swoole_server_coro: report fatal accept failure
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $socket = new class {
        public int $errCode = SOCKET_ECONNRESET;

        public string $errMsg = 'Connection reset by peer';

        public function setProtocol(array $setting): bool
        {
            return true;
        }

        public function accept(): false
        {
            return false;
        }
    };

    $server = new class($socket) extends Swoole\Coroutine\Server {
        public function __construct(object $socket)
        {
            $this->socket = $socket;
        }
    };
    $server->handle(static function (): void {});

    Assert::false($server->start());
    Assert::same($server->errCode, SOCKET_ECONNRESET);
    echo "DONE\n";
});
?>
--EXPECTF--
Warning: accept failed, Error: Connection reset by peer[%d] in %s on line %d
DONE
