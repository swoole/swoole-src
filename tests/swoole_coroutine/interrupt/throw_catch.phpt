--TEST--
swoole_coroutine: throw custom exception and catch it
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

class SleepException extends Co\Exception
{
}

class IOException extends Co\Exception
{
}

$sleep = go(function () {
    try {
        Co::sleep(999);
        echo "never here\n";
    } catch (Co\Exception $e) {
        assert($e->getLine() === __LINE__ - 3);
        assert($e->getFile() === __FILE__);
        assert($e->getCode() === SWOOLE_ERROR_CO_INTERRUPTED_BY_EXCEPTION);
        assert($e->getOriginCid() === 3);
        assert($e->getOriginFile() === __FILE__);
        assert($e->getOriginLine() === $GLOBALS['THROW_LINE'] + 1);
        assert($e->getOriginTrace()[0]['function'] === 'co_throw');
        assert(Co::wasCancelled());
        echo "{$e->getMessage()}\n";
    }
});

$socket_io = go(function () {
    try {
        $socket = new  Co\Socket(AF_INET, SOCK_DGRAM, 0);
        $ret = $socket->recvfrom($peer, -1);
        var_dump($ret);
    } catch (Co\Exception $e) {
        assert($e->getLine() === __LINE__ - 3);
        assert($e->getFile() === __FILE__);
        assert($e->getCode() === SWOOLE_ERROR_CO_INTERRUPTED_BY_EXCEPTION);
        assert($e->getOriginCid() === 3);
        assert($e->getOriginFile() === __FILE__);
        assert($e->getOriginLine() === $GLOBALS['THROW_LINE'] + 2);
        assert($e->getOriginTrace()[0]['function'] === 'co_throw');
        assert(Co::wasCancelled());
        echo "{$e->getMessage()}\n";
    }
});

go(function () use ($sleep, $socket_io) {
    function co_throw($sleep, $socket_io)
    {
        $GLOBALS['THROW_LINE'] = __LINE__;
        Co::throw($sleep, new SleepException('sleep was interrupted', SWOOLE_ERROR_CO_INTERRUPTED_BY_EXCEPTION));
        Co::throw($socket_io, new IOException('socket io was interrupted', SWOOLE_ERROR_CO_INTERRUPTED_BY_EXCEPTION));
    }

    co_throw($sleep, $socket_io);
});

?>
--EXPECT--
sleep was interrupted
socket io was interrupted
