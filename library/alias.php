<?php
if (ini_get('swoole.use_shortname') === 'On') {
    class_alias(Swoole\Coroutine\WaitGroup::class, Co\WaitGroup::class, false);
}
