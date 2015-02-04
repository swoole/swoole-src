<?php
//创建一个inotify句柄
$fd = inotify_init();

//监听文件，仅监听修改操作，如果想要监听所有事件可以使用IN_ALL_EVENTS
$watch_descriptor = inotify_add_watch($fd, __DIR__.'/inotify.data', IN_MODIFY);

swoole_event_add($fd, function ($fd) {
    $events = inotify_read($fd);
    if ($events) {
        foreach ($events as $event) {
            echo "inotify Event :" . var_export($event, 1) . "\n";
        }
    }
});
