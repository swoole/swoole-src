<?php
function swoole_event_add(mixed $fd, ?callable $read_callback = null, ?callable $write_callback = null, ?int $events = null): bool {}

function swoole_event_set(mixed $fd, ?callable $read_callback = null, ?callable $write_callback = null, ?int $events = null): bool {}

function swoole_event_del(mixed $fd): bool {}

function swoole_event_write(mixed $fd, string $data): bool {}

function swoole_event_wait(): void {}

function swoole_event_rshutdown(): void {}

function swoole_event_exit(): void {}

function swoole_event_defer(callable $callback): bool {}

function swoole_event_cycle(?callable $callback = null, bool $before = false): bool {}

function swoole_event_dispatch(): bool {}

function swoole_event_isset(mixed $fd, ?int $events = null): bool {}
