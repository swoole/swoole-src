<?php
function _array_walk(&$array, callable $callback, $userdata = null)
{
    foreach ($array as $key => &$item)
    {
        $callback($item, $key, $userdata);
    }
}