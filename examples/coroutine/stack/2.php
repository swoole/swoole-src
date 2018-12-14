<?php
go(function () {
    echo "before\n";
    co::sleep(0.5);
    echo "after\n";
});
echo "end\n";
    