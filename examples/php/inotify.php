<?php
// Open an inotify instance
$fd = inotify_init();

// Watch __FILE__ for metadata changes (e.g. mtime)
$watch_descriptor = inotify_add_watch($fd, __DIR__ . '/php', IN_MODIFY | IN_MOVED_FROM | IN_CREATE | IN_DELETE | IN_ISDIR);

while (true)
{
    // Read events
    $events = inotify_read($fd);
    print_r($events);
}

