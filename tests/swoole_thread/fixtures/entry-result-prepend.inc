<?php
if (class_exists(Swoole\Thread::class, false) && !Swoole\Thread::getInfo()['is_main_thread']) {
    $GLOBALS['thread_result_order'] = 'prepend';
    return 'prepend-result';
}
