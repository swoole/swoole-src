<?php
class WaitGroup {
    private $count = 0;
    private $chan;

    function __construct() {
        $this->chan = new chan;
    }

    function add() {
        $this->count++;
    }

    function done() {
        $this->chan->push(true);
    }

    function wait() {
        while ($this->count--) {
            $this->chan->pop();
        }
    }
}

go(function () {
    $wg = new WaitGroup;

    for($i=0;$i<10;$i++) {
        $wg->add();
        go(function() use ($wg, $i) {
            co::sleep(.3);
            echo "hello $i\n";
            $wg->done();
        });
    }

    $wg->wait();
    echo "all done\n";
});
