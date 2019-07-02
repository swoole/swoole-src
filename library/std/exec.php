<?php
function swoole_exec(string $command, &$output = null, &$returnVar = null)
{
    $result = Swoole\Coroutine::exec($command);
    if ($result) {
        $outputList = explode(PHP_EOL, $result['output']);
        if ($output) {
            $output = array_merge($output, $outputList);
        } else {
            $output = $outputList;
        }
        $returnVar = $result['code'];
        return end($outputList);
    } else {
        return false;
    }
}

function swoole_shell_exec(string $cmd)
{
    $result = Swoole\Coroutine::exec($cmd);
    if ($result && '' !== $result['output']) {
        return $result['output'];
    }
    return null;
}
