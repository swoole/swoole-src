<?php

function swoole_timer_set(array $settings): void {}

function swoole_timer_tick(int $ms, callable $callback, mixed ...$params): false|int {}

function swoole_timer_after(int $ms, callable $callback, mixed ...$params): false|int {}

function swoole_timer_exists(int $timer_id): bool {}

function swoole_timer_info(int $timer_id): ?array {}

function swoole_timer_stats(): array {}

function swoole_timer_list(): Swoole\Timer\Iterator {}

function swoole_timer_clear(int $timer_id): bool {}

function swoole_timer_clear_all() : bool {}
