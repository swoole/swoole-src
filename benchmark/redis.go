package main

import (
    "fmt"
    "log"
    "net/http"
    "github.com/hoisie/redis"
    "runtime"
)

var (
    client *redis.Client
)

func main() {

    client = &redis.Client{
        Addr:        "127.0.0.1:6379",
        Db:          0,
        MaxPoolSize: 10000,
    }
    
    // 限制为CPU的数量减一
    runtime.GOMAXPROCS( runtime.NumCPU() - 1 )

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        result, err := client.Get("hello")
        if err != nil {
            fmt.Fprint(w, err.Error())
            println(err.Error())
        } else {
            fmt.Fprint(w, "<h1>Hello world!. result="+ string(result)+"</h1>")
        }
    })

    log.Fatal(http.ListenAndServe(":8080", nil))
}
