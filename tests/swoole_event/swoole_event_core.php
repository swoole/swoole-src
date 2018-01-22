
<?php
function dnsLookup() {
    swoole_async_dns_lookup("www.qq.com", function($host, $ip) {
        swoole_event_exit();
        exit();
    });
}

$i = 200;
while (--$i) {
    $pid = pcntl_fork();
    if ($pid < 0) {
        exit;
    }

    if ($pid === 0) {
        dnsLookup();
        exit();
    }

    pcntl_waitpid($pid, $status);
    if (!pcntl_wifexited($status)) {
        fprintf(STDERR, "$pid %s exit [exit_status=%d, stop_sig=%d, term_sig=%d]\n",
            pcntl_wifexited($status) ? "normal": "abnormal",
            pcntl_wexitstatus($status),
            pcntl_wstopsig($status),
            pcntl_wtermsig($status)
        );
        exit(1);
    }
}
echo "SUCCESS";
?>

