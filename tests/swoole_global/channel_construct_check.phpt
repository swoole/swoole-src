--TEST--
swoole_global: socket construct check
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $chan = new class () extends Co\Channel
    {
        public function __construct($size = 1)
        {
            // parent::__construct($size);  // without parent call
        }
    };
    $chan->push('123');
});
?>
--EXPECTF--
Fatal error: Swoole\Coroutine\Channel::push(): you must call Channel constructor first in %s on line %d
