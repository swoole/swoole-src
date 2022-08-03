--TEST--
swoole_event: swoole_event_wait (auto)
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
register_shutdown_function(function () {
    echo "register 1\n";
    register_shutdown_function(function () {
        echo "register 3\n";
        register_shutdown_function(function () {
            echo "register 7\n";
        });
    });
});

go(function () {
    co::sleep(0.1);
    register_shutdown_function(function () {
        echo "register 4\n";
    });
    register_shutdown_function(function () {
        echo "register 5\n";
    });
});

register_shutdown_function(function () {
    echo "register 2\n";
    register_shutdown_function(function () {
        echo "register 6\n";
        register_shutdown_function(function () {
            echo "register 8\n";
        });
    });
});
?>
--EXPECT--
register 1
register 2
register 3
register 4
register 5
register 6
register 7
register 8
