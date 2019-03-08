--TEST--
swoole_coroutine: check if is in the coroutine
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$map = [
    function () {
        Co::sleep(0.0001);
        assert(0); // never here
    },
    function () {
        Co::yield();
    },
    function () {
        defer(function () { });
    },
    function () {
        $chan = new Chan;
        $chan->push('foo');
        $chan->push('bar');
        assert(0); // never here
    },
    function () {
        (new Chan)->pop();
        assert(0); // never here
    },
    function () {
        Co::fread(STDIN);
        assert(0); // never here
    },
    function () {
        Co::fgets(fopen(__FILE__, 'r'));
        assert(0); // never here
    },
    function () {
        Co::fwrite(fopen(TEST_LOG_FILE, 'w+'), 'foo');
        assert(0); // never here
    },
    function () {
        Co::readFile(__FILE__);
        assert(0); // never here
    },
    function () {
        Co::writeFile(TEST_LOG_FILE, 'foo');
        assert(0); // never here
    },
    function () {
        Co::gethostbyname('www.swoole.com');
        assert(0); // never here
    },
    function () {
        Co::getaddrinfo('www.swoole.com');
        assert(0); // never here
    },
    // function () {
    // Co::statvfs(__DIR__); // can use outside the coroutine
    // },
    function () {
        Co::exec('echo');
        assert(0); // never here
    },
    function () {
        swoole_async_dns_lookup_coro('127.0.0.1');
        assert(0); // never here
    },
    function () {
        (new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP))->connect('127.0.0.1', 1234);
        assert(0); // never here
    },
    function () {
        (new Co\Client(SWOOLE_SOCK_TCP))->connect('127.0.0.1', 1234);
        assert(0); // never here
    },
    function () {
        (new Co\Http\Client('127.0.0.1', 1234))->get('/');
        assert(0); // never here
    },
    function () {
        (new Co\Mysql)->connect([
            'host' => MYSQL_SERVER_HOST,
            'user' => MYSQL_SERVER_USER,
            'password' => MYSQL_SERVER_PWD,
            'database' => MYSQL_SERVER_DB
        ]);
        assert(0); // never here
    },
    function () {
        (new Co\Redis)->connect('127.0.0.1', 6379);
        assert(0); // never here
    },
];
if (class_exists(Co\Postgresql::class)) {
    $map[] = function () {
        (new Co\Postgresql())->connect('host=127.0.0.1 port=12345 dbname=test user=root password=root');
        assert(0); // never here
    };
}
if (class_exists(Co\Http2\Client::class)) {
    $map[] = function () {
        (new Co\Http2\Client('127.0.0.1', 1234))->connect();
        assert(0); // never here
    };
}
foreach ($map as $i => $f) {
    $GLOBALS['f'] = $f;
    $process = new Swoole\Process(function () {
        function a()
        {
            b();
        }

        function b()
        {
            c();
        }

        function c()
        {
            try {
                $GLOBALS['f']();
            } catch (Error $e) {
                // can not be caught
            }
        }

        a();
    }, true);
    $process->start();
    $info = $process->read(8192);
    $process::wait();
    $info = preg_replace('/.+(: API must be called in the coroutine)/', '%s$1', $info);
    $info = preg_replace('/\b\:\d+\b/', ':%d', $info);
    $info = preg_replace('/\[[^\]]+tests\/swoole_coroutine[^:]+/', '[%s', $info);
    $info = preg_replace('/(#0 +)[^(]+/', '$1%s', $info);
    $info = preg_replace('/^\[[^\]]+]/', '[%s]', $info);
    $info_list[] = $info;
    if ($i == 0) {
        echo $info . PHP_EOL;
    } else {
        if (!assert($info_list[0] === $info)) {
            var_dump($map[$i]);
            var_dump($info_list[0]);
            var_dump($info);
            exit;
        }
    }
}
?>
--EXPECT--
[%s]	ERROR	(PHP Fatal Error: 10001):
%s: API must be called in the coroutine
Stack trace:
#0  %s() called at [%s:%d]
#1  {closure}() called at [%s:%d]
#2  c() called at [%s:%d]
#3  b() called at [%s:%d]
#4  a() called at [%s:%d]
#5  {closure}()
#6  Swoole\Process->start() called at [%s:%d]
