--TEST--
swoole_coroutine: check if is in the coroutine
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

define('RUN_IN_CHILD', true);

$map = [
    function () {
        Co::sleep(0.001);
        Assert::assert(0); // never here
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
        Assert::assert(0); // never here
    },
    function () {
        (new Chan)->pop();
        Assert::assert(0); // never here
    },
    function () {
        Co::fread(STDIN);
        Assert::assert(0); // never here
    },
    function () {
        Co::fgets(fopen(__FILE__, 'r'));
        Assert::assert(0); // never here
    },
    function () {
        Co::fwrite(fopen(TEST_LOG_FILE, 'w+'), 'foo');
        Assert::assert(0); // never here
    },
    function () {
        Co::readFile(__FILE__);
        Assert::assert(0); // never here
    },
    function () {
        Co::writeFile(TEST_LOG_FILE, 'foo');
        Assert::assert(0); // never here
    },
    function () {
        Co::gethostbyname('www.swoole.com');
        Assert::assert(0); // never here
    },
    function () {
        Co::getaddrinfo('www.swoole.com');
        Assert::assert(0); // never here
    },
//    function () {
//        Co::statvfs(__DIR__);
//    },
    function () {
        Co::exec('echo');
        Assert::assert(0); // never here
    },
    function () {
        swoole_async_dns_lookup_coro('127.0.0.1');
        Assert::assert(0); // never here
    },
    function () {
        (new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP))->connect('127.0.0.1', 1234);
        Assert::assert(0); // never here
    },
    function () {
        (new Co\Client(SWOOLE_SOCK_TCP))->connect('127.0.0.1', 1234);
        Assert::assert(0); // never here
    },
    function () {
        (new Co\Http\Client('127.0.0.1', 1234))->get('/');
        Assert::assert(0); // never here
    },
    function () {
        (new Co\Mysql)->connect([
            'host' => MYSQL_SERVER_HOST,
            'port' => MYSQL_SERVER_PORT,
            'user' => MYSQL_SERVER_USER,
            'password' => MYSQL_SERVER_PWD,
            'database' => MYSQL_SERVER_DB
        ]);
        Assert::assert(0); // never here
    },
    function () {
        (new Co\Redis)->connect('127.0.0.1', 6379);
        Assert::assert(0); // never here
    },
];

function pgsql_test() {
    (new Co\Postgresql())->connect('host=127.0.0.1 port=12345 dbname=test user=root password=root');
    Assert::assert(0); // never here
}

if (class_exists(Co\Postgresql::class)) {
    $map[] = function () {
        pgsql_test();
    };
}
if (class_exists(Co\Http2\Client::class)) {
    $map[] = function () {
        (new Co\Http2\Client('127.0.0.1', 1234))->connect();
        Assert::assert(0); // never here
    };
}
$info_list = [];
foreach ($map as $i => $f) {
    $GLOBALS['f'] = $f;
    if (RUN_IN_CHILD == false) {
        $f();
        continue;
    }
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
    if (Assert::contains($info, 'Swoole\\Error')) {
        $_info = trim($info);
        $_info = preg_replace('/(\#0.+?: )[^\n]+/', '$1%s', $_info, 1);
        $_info = preg_replace('/(: )[^\n]+( in )/', '$1%s$2', $_info, 1);
        $_info = preg_replace('/\/[^(:]+:?\(?\d+\)?/', '%s:%d', $_info);
        $info_list[] = $_info;
        if (!Assert::assert($info_list[0] === $_info)) {
            var_dump($map[$i]);
            var_dump($info_list[0]);
            var_dump($info);
            exit;
        }
    }
}
echo current($info_list);
Swoole\Event::wait();
?>
--EXPECT--
Fatal error: %s in %s:%d
Stack trace:
#0 %s:%d: %s
#1 %s:%d: {closure}()
#2 %s:%d: c()
#3 %s:%d: b()
#4 %s:%d: a()
#5 [internal function]: {closure}(Object(Swoole\Process))
#6 %s:%d: Swoole\Process->start()
#7 {main}
  thrown in %s:%d
