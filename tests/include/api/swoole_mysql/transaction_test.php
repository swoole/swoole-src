<?php

//$const = [
//MYSQLI_TRANS_START_NO_OPT,
//MYSQLI_TRANS_START_WITH_CONSISTENT_SNAPSHOT,
//MYSQLI_TRANS_START_READ_WRITE,
//MYSQLI_TRANS_START_READ_ONLY,
//
//MYSQLI_TRANS_COR_NO_OPT,
//MYSQLI_TRANS_COR_AND_CHAIN,
//MYSQLI_TRANS_COR_AND_NO_CHAIN,
//MYSQLI_TRANS_COR_RELEASE,
//MYSQLI_TRANS_COR_NO_RELEASE
//];
//var_dump($const);exit;
//
//
//$const = [
//    // for begin_tx
//    MYSQLI_TRANS_START_WITH_CONSISTENT_SNAPSHOT,
//    MYSQLI_TRANS_START_READ_WRITE,
//    MYSQLI_TRANS_START_READ_ONLY,
//
//    // for commit and rollback
//    MYSQLI_TRANS_COR_AND_CHAIN,
//    MYSQLI_TRANS_COR_AND_NO_CHAIN,
//    MYSQLI_TRANS_COR_RELEASE,
//    MYSQLI_TRANS_COR_NO_RELEASE
//];
/*
#define TRANS_START_NO_OPT						0
#define TRANS_START_WITH_CONSISTENT_SNAPSHOT	1
#define TRANS_START_READ_WRITE					2
#define TRANS_START_READ_ONLY					4

#define TRANS_COR_NO_OPT		0
#define TRANS_COR_AND_CHAIN		1
#define TRANS_COR_AND_NO_CHAIN	2
#define TRANS_COR_RELEASE		4
#define TRANS_COR_NO_RELEASE	8
*/

function begin_transaction(\mysqli $conn, $flags)
{
    $characteristic = [];
    if ($flags & MYSQLI_TRANS_START_WITH_CONSISTENT_SNAPSHOT) {
        $characteristic[] = "WITH CONSISTENT SNAPSHOT";
    }
    if ($flags & (MYSQLI_TRANS_START_READ_ONLY | MYSQLI_TRANS_START_READ_WRITE)) {
        if ($conn->server_version < 50605) {
            trigger_error(E_USER_WARNING, "This swoole_server version doesn't support 'READ WRITE' and 'READ ONLY'. Minimum 5.6.5 is required");
        } else if ($flags & MYSQLI_TRANS_START_READ_WRITE) {
            $characteristic[] = "READ WRITE";
        } else if ($flags & MYSQLI_TRANS_START_READ_ONLY) {
            $characteristic[] = "READ ONLY";
        }
    }

    $query = "START TRANSACTION " . implode(", ", $characteristic);
}


function commit(\mysqli $conn, $flags = 0)
{
    commit_or_rollback($conn, true, $flags);
}

function rollback(\mysqli $conn, $flags = 0)
{
    commit_or_rollback($conn, false, $flags);
}

function commit_or_rollback(\mysqli $conn, $commit, $flags)
{
    $ops = [];
    if ($flags & MYSQLI_TRANS_COR_AND_CHAIN && !($flags & MYSQLI_TRANS_COR_AND_NO_CHAIN)) {
        $ops[] = "AND CHAIN";
	} else if ($flags & MYSQLI_TRANS_COR_AND_NO_CHAIN && !($flags & MYSQLI_TRANS_COR_AND_CHAIN)) {
        $ops[] = "AND NO CHAIN";
	}

    if ($flags & MYSQLI_TRANS_COR_RELEASE && !($flags & MYSQLI_TRANS_COR_NO_RELEASE)) {
        $ops[] = "RELEASE";
	} else if ($flags & MYSQLI_TRANS_COR_NO_RELEASE && !($flags & MYSQLI_TRANS_COR_RELEASE)) {
        $ops[] = "NO RELEASE";
	}

    $query = ($commit ? "COMMIT " : "ROLLBACK ") . implode(" ", $ops);
}
