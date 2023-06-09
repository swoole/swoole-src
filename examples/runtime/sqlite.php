<?php
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);

run(function() {
    $db = new PDO('sqlite::memory:');
    for ($i = 0; $i < 10; $i++) {
        go(function() use($i, $db) {
            $db->query('select randomblob(99999999)');
            var_dump($i);
        });
    }
});
