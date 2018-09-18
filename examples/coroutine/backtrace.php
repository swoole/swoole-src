<?php
function test1() {
    test2();
}

function test2() {
    while(true) {
        co::sleep(10);
        echo __FUNCTION__." \n";
    }
}

$cid = go(function () {
    test1();
});

go(function () use ($cid) {
    while(true) {
        echo "BackTrace[$cid]:\n-----------------------------------------------\n";
        echo get_debug_print_backtrace(co::getBackTrace($cid))."\n";
        co::sleep(3);
    }
});

function get_debug_print_backtrace($traces){
    $ret = array();
    foreach($traces as $i => $call){
        $object = '';
        if (isset($call['class'])) {
            $object = $call['class'].$call['type'];
            if (is_array($call['args'])) {
                foreach ($call['args'] as &$arg) {
                    get_arg($arg);
                }
            }
        }

        $ret[] = '#'.str_pad($i - $traces_to_ignore, 3, ' ')
        .$object.$call['function'].'('.implode(', ', $call['args'])
        .') called at ['.$call['file'].':'.$call['line'].']';
    }

    return implode("\n",$ret);
}

function get_arg(&$arg) {
    if (is_object($arg)) {
        $arr = (array)$arg;
        $args = array();
        foreach($arr as $key => $value) {
            if (strpos($key, chr(0)) !== false) {
                $key = '';    // Private variable found
            }
            $args[] =  '['.$key.'] => '.get_arg($value);
        }

        $arg = get_class($arg) . ' Object ('.implode(',', $args).')';
    }
}
