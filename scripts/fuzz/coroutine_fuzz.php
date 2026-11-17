<?php
/**
 * Randomized fuzzer for timers, channels, coroutine scheduling and the coroutine servers.
 *
 * Usage: php -d extension=modules/swoole.so scripts/fuzz/coroutine_fuzz.php [seconds=20] [seed=random]
 *
 * Inside one scheduler, random coroutines push/pop/close channels with random capacities and timeouts, create,
 * clear and re-arm timers from inside timer callbacks, cancel or join coroutines, use WaitGroup/Lock/Context,
 * while Coroutine\Http\Server and Coroutine\Server are attacked with random clients that drop connections at
 * random times. The run fails when the process crashes, hangs (watchdog) or exceeds the resource limits.
 */

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http\Server as HttpServer;
use Swoole\Coroutine\Server as TcpServer;
use Swoole\Coroutine\Socket;
use Swoole\Coroutine\WaitGroup;
use Swoole\Timer;

use function Swoole\Coroutine\run;

$duration = (int) ($argv[1] ?? 20);
$seed = isset($argv[2]) && $argv[2] !== 'random' ? (int) $argv[2] : random_int(1, PHP_INT_MAX >> 1);
mt_srand($seed);
echo "seed=$seed duration={$duration}s\n";

const MAX_COROUTINES = 3000;
const MAX_TIMERS = 3000;

function pick(array $items)
{
    return $items[mt_rand(0, count($items) - 1)];
}

function ms(int $max): float
{
    return mt_rand(1, $max + 1) / 1000;
}

$stat = ['chan_ops' => 0, 'timers' => 0, 'cancel' => 0, 'clients' => 0];
$stop = false;

// Real coroutine work only; each actor takes one random step, then returns.
function chan_actor(Channel $ch, array &$stat): void
{
    $stat['chan_ops']++;
    switch (mt_rand(0, 9)) {
    case 0:
    case 1:
        $ch->push(str_repeat('x', mt_rand(0, 64)), pick([-1, 0, 0.001, 0.01]));
        break;
    case 2:
    case 3:
        $ch->pop(pick([-1, 0, 0.001, 0.01]));
        break;
    case 4:
        $ch->close();
        break;
    case 5:
        $ch->stats();
        $ch->isEmpty();
        $ch->isFull();
        $ch->length();
        break;
    case 6:
        $ch->push(['a' => $ch], 0.002);  // reference cycle through the channel
        break;
    case 7:
        Coroutine::sleep(ms(3));
        $ch->pop(0.001);
        break;
    case 8:
        $ch->push(1, -1);
        break;
    default:
        $ch->pop(-1);
    }
}

function timer_actor(array &$stat, array &$timers): void
{
    $stat['timers']++;
    if (count($timers) > MAX_TIMERS) {
        Timer::clear(array_shift($timers));
    }
    switch (mt_rand(0, 9)) {
    case 0:
    case 1:
        $timers[] = Timer::after(mt_rand(1, 20), function () use (&$timers, &$stat) {
            timer_actor($stat, $timers);
        });
        break;
    case 2:
        $id = Timer::tick(mt_rand(1, 10), function (int $tid) use (&$timers, &$stat) {
            static $n = [];
            $n[$tid] = ($n[$tid] ?? 0) + 1;
            if ($n[$tid] > mt_rand(1, 5)) {
                Timer::clear($tid);
                unset($n[$tid]);
            }
            if (mt_rand(0, 3) === 0) {
                timer_actor($stat, $timers);
            }
        });
        $timers[] = $id;
        break;
    case 3:
        if ($timers) {
            Timer::clear($timers[array_rand($timers)]);  // may already be gone or running
        }
        break;
    case 4:
        // clear itself from inside its own callback, then clear again
        $timers[] = Timer::after(mt_rand(1, 5), function () use (&$timers) {
            if ($timers) {
                $id = array_pop($timers);
                Timer::clear($id);
                Timer::clear($id);
            }
        });
        break;
    case 5:
        if ($timers) {
            Timer::info($timers[array_rand($timers)]);
            Timer::exists($timers[array_rand($timers)]);
            Timer::stats();
        }
        break;
    case 6:
        if (mt_rand(0, 40) === 0) {
            Timer::clearAll();
            $timers = [];
        }
        break;
    case 7:
        // timer callback that sleeps / blocks on a channel (runs in its own coroutine)
        $timers[] = Timer::after(mt_rand(1, 5), function () {
            $ch = new Channel(1);
            Coroutine::sleep(ms(3));
            $ch->pop(0.002);
        });
        break;
    case 8:
        Timer::after(mt_rand(1, 2), function () {
            try {
                throw new Exception('fuzz');
            } catch (Exception $e) {
            }
        });
        break;
    default:
        $timers[] = Timer::after(mt_rand(1, 3), static function () {
        });
    }
}

function coroutine_actor(array &$stat, array &$cids): void
{
    if (count($cids) > MAX_COROUTINES) {
        $cids = array_slice($cids, -500);
    }
    switch (mt_rand(0, 10)) {
    case 8:
        $cids[] = go(function () {
            switch (mt_rand(0, 4)) {
            case 0:
                Coroutine::readFile(__FILE__);
                break;
            case 1:
                Coroutine::gethostbyname('localhost');
                break;
            case 2:
                Coroutine::exec('true');
                break;
            case 3:
                Coroutine::writeFile('/tmp/swoole_co_fuzz_' . getmypid(), 'x');
                break;
            default:
                Coroutine::getaddrinfo('localhost');
            }
        });
        if (mt_rand(0, 1)) {
            Coroutine::cancel(end($cids));
        }
        break;
    case 9:
        $cids[] = go(function () {
            $ch = new Channel(0);
            go(function () use ($ch) {
                $ch->pop(-1);
            });
            Coroutine::sleep(ms(2));
            $ch->close();
            $ch->push(1);
        });
        break;
    case 10:
        $cids[] = go(function () {
            $c = new Swoole\Coroutine\Http\Client('127.0.0.1', 19400 + getmypid() % 100);
            $c->set(['timeout' => ms(5)]);
            $c->get('/');
            $c->close();
        });
        if (mt_rand(0, 2) === 0) {
            Coroutine::cancel(end($cids));
        }
        break;
    case 0:
        $cids[] = Coroutine::create(function () {
            Coroutine::sleep(ms(50));
        });
        break;
    case 1:
        if ($cids) {
            $stat['cancel']++;
            Coroutine::cancel($cids[array_rand($cids)]);
        }
        break;
    case 2:
        if ($cids) {
            Coroutine::join([$cids[array_rand($cids)]], 0.005);
        }
        break;
    case 3:
        $wg = new WaitGroup();
        for ($i = mt_rand(1, 5); $i > 0; $i--) {
            $wg->add();
            go(function () use ($wg) {
                Coroutine::sleep(ms(3));
                $wg->done();
            });
        }
        $wg->wait(0.01);
        break;
    case 4:
        $lock = new Swoole\Coroutine\Lock(SWOOLE_MUTEX);
        $lock->lock();
        $cids[] = go(function () use ($lock) {
            $lock->lock();
            $lock->unlock();
        });
        Coroutine::sleep(ms(2));
        $lock->unlock();
        break;
    case 5:
        $cids[] = go(function () {
            defer(function () {
                Coroutine::sleep(ms(2));
            });
            Coroutine::yield();
        });
        $cid = end($cids);
        Timer::after(mt_rand(1, 5), function () use ($cid) {
            Coroutine::resume($cid);
        });
        break;
    case 6:
        Coroutine::getContext()['x'] = str_repeat('y', mt_rand(0, 100));
        Coroutine::stats();
        Coroutine::list();
        break;
    default:
        // channel + timer interplay: a timer closes a channel that coroutines are blocked on
        $ch = new Channel(mt_rand(0, 3));
        for ($i = mt_rand(1, 4); $i > 0; $i--) {
            go(function () use ($ch, &$stat) {
                chan_actor($ch, $stat);
            });
        }
        Timer::after(mt_rand(1, 5), function () use ($ch) {
            $ch->close();
        });
    }
}

function net_client(int $http_port, int $tcp_port, array &$stat): void
{
    $sock = new Socket(AF_INET, SOCK_STREAM, 0);
    $kind = mt_rand(0, 3);
    if (!$sock->connect('127.0.0.1', $kind === 3 ? $tcp_port : $http_port, 0.5)) {
        return;
    }
    $stat['clients']++;
    switch ($kind) {
    case 0:
        $sock->send("GET /?a=1 HTTP/1.1\r\nHost: x\r\n\r\n");
        break;
    case 1:
        $sock->send("POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n" . str_repeat('a', mt_rand(0, 1500)));
        break;
    case 2:
        $sock->send("GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" .
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
        $sock->recv(1024, 0.01);
        $sock->send(random_bytes(mt_rand(1, 3000)));
        break;
    default:
        $sock->send(pack('N', mt_rand(0, 100000)) . random_bytes(mt_rand(0, 2000)));
    }
    if (mt_rand(0, 2) === 0) {
        $sock->recv(65536, ms(10));
    }
    if (mt_rand(0, 1)) {
        $sock->setOption(SOL_SOCKET, SO_LINGER, ['l_onoff' => 1, 'l_linger' => 0]);  // RST
    }
    $sock->close();
}

Coroutine::set(['max_coroutine' => 20000, 'enable_deadlock_check' => false]);
$watch = microtime(true);
run(function () use ($duration, &$stat, &$stop) {
    $http_port = 19400 + getmypid() % 100;
    $tcp_port = $http_port + 100;
    $timers = [];
    $cids = [];
    $channels = [];

    $http = new HttpServer('127.0.0.1', $http_port);
    $http->handle('/', function ($req, $resp) {
        switch (mt_rand(0, 5)) {
        case 0:
            $resp->detach();
            Coroutine::sleep(ms(3));
            $resp->close();
            break;
        case 1:
            $resp->write(str_repeat('a', mt_rand(1, 100000)));
            Coroutine::sleep(ms(3));
            $resp->end();
            break;
        case 2:
            Coroutine::sleep(ms(5));
            $resp->end('late');
            break;
        case 3:
            $resp->status(500);
            $resp->end($req->rawContent());
            break;
        case 4:
            $resp->sendfile(__FILE__);
            break;
        default:
            $resp->end('ok');
        }
    });
    $http->handle('/ws', function ($req, $ws) {
        $ws->upgrade();
        for ($i = mt_rand(0, 5); $i > 0; $i--) {
            $frame = $ws->recv(ms(10));
            if (!$frame || $frame->opcode === WEBSOCKET_OPCODE_CLOSE) {
                break;
            }
            if (mt_rand(0, 3) === 0) {
                $ws->push(str_repeat('p', mt_rand(0, 50000)));
            }
        }
        if (mt_rand(0, 1)) {
            $ws->close();
        }
    });
    go(function () use ($http) {
        $http->start();
    });

    $tcp = new TcpServer('127.0.0.1', $tcp_port, false, true);
    $tcp->set(['open_length_check' => true, 'package_length_type' => 'N', 'package_length_offset' => 0,
        'package_body_offset' => 4, 'package_max_length' => 1 << 20]);
    $tcp->handle(function ($conn) {
        for ($i = mt_rand(0, 4); $i > 0; $i--) {
            $data = $conn->recv(ms(10));
            if ($data === '' || $data === false) {
                break;
            }
            if (mt_rand(0, 2) === 0) {
                $conn->send(str_repeat('r', mt_rand(1, 200000)));
            }
        }
        if (mt_rand(0, 1)) {
            $conn->close();
        }
    });
    go(function () use ($tcp) {
        $tcp->start();
    });
    Coroutine::sleep(0.1);

    $end = microtime(true) + $duration;
    $workers = 0;
    while (microtime(true) < $end) {
        for ($i = 0; $i < 40; $i++) {
            if ($workers > 1500) {
                break;
            }
            $workers++;
            $channel = mt_rand(0, 9) === 0 || !$channels ? ($channels[] = new Channel(mt_rand(0, 4))) : $channels[array_rand($channels)];
            if (count($channels) > 200) {
                array_shift($channels)->close();
            }
            go(function () use (&$stat, &$timers, &$cids, $http_port, $tcp_port, $channel, &$workers) {
                try {
                    switch (mt_rand(0, 4)) {
                    case 0:
                        chan_actor($channel, $stat);
                        break;
                    case 1:
                        timer_actor($stat, $timers);
                        break;
                    case 2:
                        coroutine_actor($stat, $cids);
                        break;
                    default:
                        net_client($http_port, $tcp_port, $stat);
                    }
                } catch (Throwable $e) {
                } finally {
                    $workers--;
                }
            });
        }
        Coroutine::sleep(0.002);
    }

    foreach ($channels as $ch) {
        $ch->close();
    }
    Coroutine::sleep(0.2);
    foreach (Coroutine::list() as $cid) {
        if ($cid !== Coroutine::getCid()) {
            Coroutine::cancel($cid);
        }
    }
    Timer::clearAll();
    $http->shutdown();
    $tcp->shutdown();
    $stop = true;
});

$rss = (int) (memory_get_peak_usage(true) / 1048576);
echo 'stats: ', json_encode($stat), " peak_mem={$rss}MB elapsed=", round(microtime(true) - $watch, 1), "s\n";
echo "seed=$seed\nRESULT: OK\n";
