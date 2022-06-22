#include "phpx_embed.h"
#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

using namespace php;
using namespace std;

int main(int argc, char * argv[])
{
    VM vm(argc, argv);
    cout << "hello world" << endl;

    char buf[8192];
    ssize_t n;

    int fd = 0;
    if (argc > 0) {
        fd = open(argv[1], O_RDONLY);
    }

    n = read(fd, buf, 8192);
    if (n < 0) {
        fprintf(stderr, "failed to read data\n");
        return 1;
    }

    auto req_var = exec("Swoole\\Http\\Request::create");

    var_dump(req_var);

    if (!req_var.isObject()) {
        fprintf(stderr, "cannot create object of Swoole\\Http\\Request\n");
        return 2;
    }

    Variant data(buf, n);

    auto req = Object(req_var);
    auto retval = req.exec("parse", data);

    printf("retval=%ld", retval.toInt());

    var_dump(req);

    return 0;
}
