<?php

namespace Swoole\Coroutine {

    function run(callable $fn, ...$args)
    {
        $s = new Scheduler();
        $s->add($fn, ...$args);
        return $s->start();
    }

}

namespace Co {

    if (ini_get('swoole.use_shortname') === 'On') {
        function run(callable $fn, ...$args)
        {
            return \Swoole\Coroutine\Run($fn, ...$args);
        }
    }

}
