<?php
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
    exit(1);
}

go(function () {
    try {
        route();
    } catch (\Swoole\ExitException $e) {
        assert($e->getStatus() === 1);
        assert($e->getFlags() === SWOOLE_EXIT_IN_COROUTINE);
        return;
    }
});
