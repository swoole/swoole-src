package main

import (
    "fmt"
    "log"
    "net/http"
    "runtime"
)

func main() {
    // 限制为CPU的数量减一
    runtime.GOMAXPROCS( runtime.NumCPU() - 1 )

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprint(w, "<h1>Hello world!</h1>")
    })

    log.Printf("Go http Server listen on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
