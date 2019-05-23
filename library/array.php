<?php
function swoole_array_walk(&$array, callable $callback, $userdata = null)
{
    foreach ($array as $key => &$item) {
        $callback($item, $key, $userdata);
    }
}

function swoole_array_walk_recursive(&$array, callable $callback, $userdata = null)
{
    foreach ($array as $key => &$item) {
        if (is_array($item)) {
            swoole_array_walk_recursive($item, $callback, $userdata);
        } else {
            $callback($item, $key, $userdata);
        }
    }
}