<?php

namespace SwooleBench\Command;

use SwooleBench\Base;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Exception\LogicException;

class RunTest extends Command
{
    protected function configure()
    {
        $this->addArgument(
            'method',
            InputArgument::REQUIRED,
            'Who do you want to test?'
        );
        $this->addOption('concurrent', 'c', InputOption::VALUE_REQUIRED);
        $this->addOption('requests', 'r', InputOption::VALUE_REQUIRED, 'number or requests');
        $this->addOption('server', 's', InputOption::VALUE_REQUIRED, 'server ip:port');
        $this->addOption('length', 'l', InputOption::VALUE_OPTIONAL, 'data length');
        $this->addOption('writeonly', '', InputOption::VALUE_NONE, 'write only');
        $this->setName('run');
        $this->setHelp("run benchmark test");
        $this->setDescription("Run benchmark test.");
        $this->addUsage('e.g: ./main -c 100 -r 10000 127.0.0.1:9501 length');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $c = $input->getOption('concurrent');
        if (!$c) {
            throw new LogicException('Please enter the number of concurrent.');
        }

        $n = $input->getOption('requests');
        if (!$n) {
            throw new LogicException('Please enter the number of requests.');
        }

        $s = $input->getOption('server');
        if (!$s) {
            throw new LogicException('Please enter the server ip:port.');
        }

        $f = $input->getArgument('method');
        $test = new Base($c, $n, $s, $f);

        if ($input->hasOption('length')) {
            $len = $input->getOption('length');
            $test->setDataLength($len);
        }

        if ($input->getOption('verbose')) {
            $test->verbose = true;
        }

        if ($input->getOption('writeonly')) {
            $test->writeOnly = true;
        }

        $test->run();
    }
}