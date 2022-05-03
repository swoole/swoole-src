<?php
/**
 * User: lufei
 * Date: 2020/8/16
 * Email: lufei@swoole.com
 */

Co::set(['hook_flags' => SWOOLE_HOOK_BLOCKING_FUNCTION]);

Co\run(function () {
    echo shell_exec('ls');
});
