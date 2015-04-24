package main

import (
    "bufio"
    "fmt"
    "net"
    "runtime"
)

func Echo(c net.Conn) {
    defer c.Close()
    for {
        line, err := bufio.NewReader(c).ReadString('\n')
        if err != nil {
            //fmt.Printf("Failure to read:%s\n", err.Error())
            return
        }
        _, err = c.Write([]byte(line))
        if err != nil {
            //fmt.Printf("Failure to write: %s\n", err.Error())
            return
        }
    }
}

func main() {

    runtime.GOMAXPROCS(runtime.NumCPU() - 1)

    fmt.Printf("Server is ready...\n")
    l, err := net.Listen("tcp", ":8053")
    if err != nil {
        fmt.Printf("Failure to listen: %s\n", err.Error())
    }

    for {
        if c, err := l.Accept(); err == nil {
            go Echo(c) //new thread
        }
    }
}
