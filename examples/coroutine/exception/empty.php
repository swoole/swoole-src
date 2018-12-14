<?php
go(function () {
    try {
        echo "before\n";
        co::sleep(0.5);
        echo "after\n";
        throw new Exception('coro Exception.');
    } catch (Exception $e) {
        echo 'Caught exception: ',  $e->getMessage(), "\n";
    } finally {
        echo "First finally.\n";
    }
});
echo "exec file end\n";
