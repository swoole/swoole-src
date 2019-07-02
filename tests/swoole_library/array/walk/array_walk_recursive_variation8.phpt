--TEST--
swoole_library/array/walk: usage variations - buit-in function as callback
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

/* Prototype  : bool array_walk_recursive(array $input, string $funcname [, mixed $userdata])
 * Description: Apply a user function to every member of an array
 * Source code: ext/standard/array.c
*/

/*
 * Passing different buit-in functionns as callback function
 *    pow function
 *    min function
 *    echo language construct
*/
go(function(){
    echo "*** Testing array_walk_recursive() : built-in function as callback ***\n";
    
    $input = [[2 => 1, 65], [98, 100], [6 => -4]];
    
    echo "-- With 'pow' built-in function --\n";
    var_dump(array_walk_recursive($input, 'pow'));
    
    echo "-- With 'min' built-in function --\n";
    var_dump(array_walk_recursive($input, "min"));
    
    echo "-- With 'echo' language construct --\n";
    try {
        var_dump(array_walk_recursive($input, "echo"));
    } catch (TypeError $e) {
        echo $e->getMessage(), "\n";
    }
    
    echo "Done";
});
?>
--EXPECTF--
*** Testing array_walk_recursive() : built-in function as callback ***
-- With 'pow' built-in function --
bool(true)
-- With 'min' built-in function --
bool(true)
-- With 'echo' language construct --
Argument 2 passed to %Aarray_walk_recursive() must be callable, string given
Done
