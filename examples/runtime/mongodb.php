<?php
use function Swoole\Coroutine\run;

Swoole\Runtime::setHookFlags(SWOOLE_HOOK_ALL | SWOOLE_HOOK_MONGODB);

run(function() {
    $client = new MongoDB\Client('mongodb://127.0.0.1:27017');
    $list = $client->listDatabases();
    echo "Available databases:\n";
    foreach ($list as $database) {
        echo "- Name: {$database->getName()}\n";
        echo "  Size: {$database->getSizeOnDisk()} bytes\n";
        echo "  Empty: " . ($database->isEmpty() ? 'Yes' : 'No') . "\n";
        echo "---\n";
    }
});
