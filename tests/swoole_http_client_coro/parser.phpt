--TEST--
swoole_http_client_coro: http header field normal chars
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('curl_init');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

//    static const uint8_t normal_url_char[256] = {
//        /*   0 nul    1 soh    2 stx    3 etx    4 eot    5 enq    6 ack    7 bel  */
//        0,       0,       0,       0,       0,       0,       0,       0,
//    /*   8 bs     9 ht    10 nl    11 vt    12 np    13 cr    14 so    15 si   */
//            0,       0,       0,       0,       0,       0,       0,       0,
//    /*  16 dle   17 dc1   18 dc2   19 dc3   20 dc4   21 nak   22 syn   23 etb */
//            0,       0,       0,       0,       0,       0,       0,       0,
//    /*  24 can   25 em    26 sub   27 esc   28 fs    29 gs    30 rs    31 us  */
//            0,       0,       0,       0,       0,       0,       0,       0,
//    /*  32 sp    33  !    34  "    35  #    36  $    37  %    38  &    39  '  */
//            0,       1,       1,       0,       1,       1,       1,       1,
//    /*  40  (    41  )    42  *    43  +    44  ,    45  -    46  .    47  /  */
//            1,       1,       1,       1,       1,       1,       1,       1,
//    /*  48  0    49  1    50  2    51  3    52  4    53  5    54  6    55  7  */
//            1,       1,       1,       1,       1,       1,       1,       1,
//    /*  56  8    57  9    58  :    59  ;    60  <    61  =    62  >    63  ?  */
//            1,       1,       1,       1,       1,       1,       1,       0,
//    /*  64  @    65  A    66  B    67  C    68  D    69  E    70  F    71  G  */
//            1,       1,       1,       1,       1,       1,       1,       1,
//    /*  72  H    73  I    74  J    75  K    76  L    77  M    78  N    79  O  */
//            1,       1,       1,       1,       1,       1,       1,       1,
//    /*  80  P    81  Q    82  R    83  S    84  T    85  U    86  V    87  W  */
//            1,       1,       1,       1,       1,       1,       1,       1,
//    /*  88  X    89  Y    90  Z    91  [    92  \    93  ]    94  ^    95  _  */
//            1,       1,       1,       1,       1,       1,       1,       1,
//    /*  96  `    97  a    98  b    99  c   100  d   101  e   102  f   103  g  */
//            1,       1,       1,       1,       1,       1,       1,       1,
//    /* 104  h   105  i   106  j   107  k   108  l   109  m   110  n   111  o  */
//            1,       1,       1,       1,       1,       1,       1,       1,
//    /* 112  p   113  q   114  r   115  s   116  t   117  u   118  v   119  w  */
//            1,       1,       1,       1,       1,       1,       1,       1,
//    /* 120  x   121  y   122  z   123  {   124  |   125  }   126  ~   127 del */
//            1,       1,       1,       1,       1,       1,       1,       0 };

/* Tokens as defined by rfc 2616. Also lowercases them.
 *        token       = 1*<any CHAR except CTLs or separators>
 *     separators     = "(" | ")" | "<" | ">" | "@"
 *                    | "," | ";" | ":" | "\" | <">
 *                    | "/" | "[" | "]" | "?" | "="
 *                    | "{" | "}" | SP | HT
 */

static $normal_chars = [
    '!',
    '"',
    '$',
    '%',
    '&',
    '\'',

    // not allowed as a start in http parser
    'x(',
    'x)',

    '*',
    '+',

    // not allowed as a start in http parser
    'x,',

    '-',
    '.',
    '/',

    // not support numeric header name in swoole
    // '0',
    // '1',
    // '2',
    // '3',
    // '4',
    // '5',
    // '6',
    // '7',
    // '8',
    // '9',

    // will be split and not allowed as a start in http parser
    // ':',

    // not allowed as a start in http parser
    'x;',
    'x<',
    'x=',
    'x>',
    'x@',

    // case insensitive
    // 'A',
    // 'B',
    // 'C',
    // 'D',
    // 'E',
    // 'F',
    // 'G',
    // 'H',
    // 'I',
    // 'J',
    // 'K',
    // 'L',
    // 'M',
    // 'N',
    // 'O',
    // 'P',
    // 'Q',
    // 'R',
    // 'S',
    // 'T',
    // 'U',
    // 'V',
    // 'W',
    // 'X',
    // 'Y',
    // 'Z',

    // not allowed as a start in http parser
    'x[',
    'x\\',
    'x]',

    '^',
    '_',
    '`',

    'a',
    'b',
    'c',
    'd',
    'e',
    'f',
    'g',
    'h',
    'i',
    'j',
    'k',
    'l',
    'm',
    'n',
    'o',
    'p',
    'q',
    'r',
    's',
    't',
    'u',
    'v',
    'w',
    'x',
    'y',
    'z',

    // not allowed as a start in http parser
    'x{',

    '|',
    '}',
    '~',
];

$pm = new ProcessManager;
$pm->initRandomData((count($normal_chars) + 1) * 2);
$pm->parentFunc = function () use ($pm, &$normal_chars) {
    // use curl
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:{$pm->getFreePort()}/");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HEADER, 1);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept-Encoding: gzip']);
    curl_setopt($ch, CURLOPT_ENCODING, "gzip");
    $output = curl_exec($ch);
    curl_close($ch);
    list($headers, $body) = explode("\r\n\r\n", $output);
    $headers = explode("\r\n", $headers);
    array_shift($headers);
    foreach ($headers as $header) {
        list($name, $value) = explode(': ', $header);
        if (in_array(strtolower($name), $normal_chars)) {
            Assert::same($value, ($s = $pm->getRandomData()));
        }
    }
    Assert::same($body, $pm->getRandomData());

    // use swoole http client
    go(function () use ($pm, &$normal_chars) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => 1]);
        Assert::assert($cli->get('/'));
        foreach ($cli->headers as $name => $value) {
            if (in_array($name, $normal_chars)) {
                Assert::same($value, $pm->getRandomData());
            }
        }
        Assert::same($cli->body, $pm->getRandomData());
    });

    swoole_event_wait();
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (swoole_http_request $request, swoole_http_response $response) use ($pm) {
        global $normal_chars;
        foreach ($normal_chars as $char) {
            $response->header($char, $pm->getRandomData());
        }
        $response->end($pm->getRandomData());
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
