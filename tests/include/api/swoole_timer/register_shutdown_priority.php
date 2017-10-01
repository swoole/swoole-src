<?php

// first shutdown func
// timer after
function func1()
{
    register_shutdown_function(function() {
        echo "first shutdown func\n";
    });

//    $start = microtime(true);
    swoole_timer_after(1, function() /*use($start)*/ {
        echo "timer after\n";
//        echo (microtime(true) - $start) * 1000 - 1;
    });
}

// first shutdown func
// timer after
function func1_2()
{
    $order4 = function() { echo "first shutdown func\n"; };
    $order5 = function() { swoole_event_wait(); };
    $order6 = function() { echo "timer after\n";};

    // order 1
    register_shutdown_function($order4);
    // order 2
    register_shutdown_function($order5);
    // order 3
    swoole_timer_after(1, $order6);
}


// timer after
// first shutdown func
function func2()
{
    register_shutdown_function(function() {
        echo "first shutdown func\n";
    });

    swoole_timer_after(1, function() {
        echo "timer after\n";
    });

    swoole_event_wait();
}


// first shutdown func
// timer after
// second shutdown func
function func3()
{
    register_shutdown_function(function() {
        echo "first shutdown func\n";
    });

    swoole_timer_after(1, function() {
        echo "timer after\n";
        register_shutdown_function(function() {
            echo "second shutdown func\n";
        });
    });

}


function recv_shutdow()
{
    register_shutdown_function(function() {
        echo "shutdown\n";
        recv_shutdow();
    });
}



//recv_shutdow();
//func1();
func1_2();
//func2();
//func3();


