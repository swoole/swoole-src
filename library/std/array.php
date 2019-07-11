<?php
function swoole_array_walk(array &$array, callable $callback, ...$userdata): bool
{
    if (($argc = func_num_args()) > 3) {
        throw new TypeError("array_walk() expects at most 3 parameters, {$argc} given");
    }
    foreach ($array as $key => &$item) {
        $callback($item, $key, ...$userdata);
    }
    return true;
}

function swoole_array_walk_recursive(array &$array, callable $callback, ...$userdata): bool
{
    if (($argc = func_num_args()) > 3) {
        throw new TypeError("array_walk_recursive() expects at most 3 parameters, {$argc} given");
    }
    foreach ($array as $key => &$item) {
        if (is_array($item)) {
            swoole_array_walk_recursive($item, $callback, ...$userdata);
        } else {
            $callback($item, $key, ...$userdata);
        }
    }
    return true;
}
