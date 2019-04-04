--TEST--
swoole_global: socket construct check
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $socket = new class (1, 2, 3) extends Co\Socket
    {
        public function __construct($domain, $type, $protocol)
        {
            // parent::__construct($domain, $type, $protocol); // without parent call
        }
    };
    $socket->connect('127.0.0.1', 12345);
});
?>
--EXPECTF--
Fatal error: Swoole\Coroutine\Socket::connect(): you must call Socket constructor first in %s on line %d
