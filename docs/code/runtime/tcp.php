<?php
/**
 * User: lufei
 * Date: 2020/8/9
 * Email: lufei@swoole.com
 */

//Co::set(['hook_flags' => SWOOLE_HOOK_TCP]);
Co::set(['hook_flags' => SWOOLE_HOOK_ALL]);

$s = microtime(true);
Co\run(function() {
    for ($c = 100; $c--;) {
        go(function () {//创建100个协程
            $redis = new Redis();
            $redis->connect('127.0.0.1', 6379);//此处产生协程调度，cpu切到下一个协程，不会阻塞进程
            $redis->get('key');//此处产生协程调度，cpu切到下一个协程，不会阻塞进程
        });
    }
});
echo 'use ' . (microtime(true) - $s) . ' s';