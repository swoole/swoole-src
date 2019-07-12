# Travis tests

  The automated test scripts in this directory can not only run on Travis CI. Powered by docker container technology, it can run on any systems. You only need to run the `route.sh` script to create containers of multiple PHP environments then it will run Swoole's build tests and unit tests on multiple systems automatically.
  
### With special branch

```shell
TRAVIS_BRANCH=alpine ./route.sh
```

### Enter the container

> You can cancel the unit test by `CTRL+C`

```shell
docker exec -it -e LINES=$(tput lines) -e COLUMNS=$(tput cols) swoole /bin/bash
```
