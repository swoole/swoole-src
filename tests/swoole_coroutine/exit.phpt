--TEST--
swoole_coroutine: exit
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

function route()
{
    controller();
}

function controller()
{
    your_code();
}

function your_code()
{
    co::sleep(.001);
    exit;
}
go(function () {
    try {
        echo "in coroutine\n";
        route();
    } catch (\Swoole\ExitException $e) {
        $flags = $e->getFlags();
        assert($flags & SWOOLE_EXIT_IN_COROUTINE);
        echo "exit coroutine\n";
        return;
    }
    echo "never here\n";
});
?>
--EXPECT--
in coroutine
exit coroutine
