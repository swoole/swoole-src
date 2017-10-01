<?php


class TcpStat
{
    const SS_NETSTAT_TCP_STATE_MAP = [
        "established"   => "ESTABLISHED",
        "syn-sent"      => "SYN_SENT",
        "syn-recv"      => "SYN_RCVD",
        "fin-wait-1"    => "FIN_WAIT_1",
        "fin-wait-2"    => "FIN_WAIT_2",
        "time-wait"     => "TIME_WAIT",
        "closed"        => "CLOSED",
        "close-wait"    => "CLOSE_WAIT",
        "last-ack"      => "LAST_ACK",
        "listen"        => "LISTEN",
        "closing"       => "CLOSING",
    ];

    public static function xCount($path)
    {
        if (PHP_OS === "Darwin") {
            $n = `netstat -x | grep $path | wc -l`;
            return intval(trim($n));
        } else {
            $n = `ss -x src $path | wc -l`;
            return intval(trim($n)) - 1;
        }
    }

    public static function count($host, $port, $states = ["established", "time-wait", "close-wait"]) {
        if (!ip2long($host)) {
            $host = gethostbyname($host);
        }

        $pipe = "wc -l";
        $func = PHP_OS === "Darwin" ?  "netstat" : "ss";
        $states = static::fmtTcpState($states, $func);

        $info = [];
        foreach ($states as $state) {
            $ret = call_user_func([static::class, $func], $host, $port, $state, $pipe);
            $info[$state] = intval(trim($ret)) - 1;
        }

        return $info;
    }

    private static function netstat($host, $port, $state, $pipe = "")
    {
        if ($pipe) {
            $pipe = " | $pipe";
        }
        // $4 src $5 dst $6 stats
        return `netstat -an | awk '(\$5 == "$host.$port" && \$6 == "$state") || NR==2  {print \$0}' $pipe`;
    }

    private static function ss($host, $port, $state, $pipe = "")
    {
        if ($pipe) {
            $pipe = " | $pipe";
        }
        return `ss state $state dst $host:$port $pipe`;
    }

    private static function fmtTcpState(array $states, $type)
    {
        $from = $to = [];
        if ($type === "ss") {
            $to = static::SS_NETSTAT_TCP_STATE_MAP;
            $from = array_flip($to);
        } else if ($type === "netstat") {
            $from = static::SS_NETSTAT_TCP_STATE_MAP;
            $to = array_flip($from);
        }

        $ret = [];
        foreach ($states as $state) {
            if (isset($to[$state])) {
                $ret[] = $state;
            } else if (isset($from[$state])) {
                $ret[] = $from[$state];
            }
        }
        return $ret;
    }
}
