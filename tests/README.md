# PHP Unit-test

Run these tests to make certain that the swoole extension you installed can work well.

## How to run
1. Run all of the test scripts on source root dir by `make test`
2. Or run `./strart.sh`
3. use`./start.sh ./swoole_*` command to run a part of the tests

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
Run `./new.sh [test-script-filename]`

E.g. : `./new.sh ./swoole-coroutine/co_sleep.phpt`

It will generate the test script file and auto open on your ide (MacOS only).

![](https://ws1.sinaimg.cn/large/006DQdzWly1frvn56azn9g30rs0m8b29.gif)