<?php
go(function () {

    defer(function () {
        co::sleep(1);
        echo "end 2\n";

        defer(function () {
            co::sleep(1);
            echo "end 3\n";
        });

        defer(function () {
            co::sleep(1);
            echo "end 5\n";
        });
    });

    defer(function () {
        co::sleep(1);
        echo "end 4\n";
    });

    echo "begin\n";
    co::sleep(1);
    echo "end 1\n";
});
