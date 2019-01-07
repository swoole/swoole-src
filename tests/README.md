# PHP Unit-test

Run these tests to make certain that the swoole extension you installed can work well.

## How to run
1. just run `./start.sh`
2. or use`./start.sh ./swoole_*` command to run a part of the tests
3. or use `./start.sh base` command to run base tests

## Defaults

| Config    | Enable   |
| --------- | -------- |
| show-diff | yes      |
| show-mem  | yes      |
| show-slow | 1000(ms) |

## Log files

| suffix | intro                                         |
| ------ | --------------------------------------------- |
| diff   | show the differents between output and expect |
| out    | script output                                 |
| exp    | expect output                                 |
| log    | all above                                     |
| php    | php temp script file                          |

## Clean
Run `./clean` to remove all of the tests log files.

## Contribute the test script
Run `./new [test-script-filename]`

E.g. : `./new ./swoole-coroutine/co_sleep.phpt`

It will generate the test script file and auto open on your ide (MacOS only).

![](https://ws1.sinaimg.cn/large/006DQdzWly1frvn56azn9g30rs0m8b29.gif)
