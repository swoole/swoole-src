package main

import (
    "log"
    "github.com/valyala/fasthttp"
    "runtime"
    "fmt"
)

func main() {
    runtime.GOMAXPROCS(runtime.NumCPU() - 1)

    m := func(ctx *fasthttp.RequestCtx) {
        switch string(ctx.Path()) {
            case "/":
                ctx.Response.Header.Set("Last-Modified", "Thu, 18 Jun 2015 10:24:27 GMT")
                ctx.Response.Header.Set("Accept-Ranges", "bytes")
                ctx.Response.Header.Set("E-Tag", "55829c5b-17")
                ctx.Response.Header.Set("Server", "golang-http-server")
                fmt.Fprint(ctx, "<h1>\nHello world!\n</h1>\n")
            default:
        }
    }

    log.Printf("Go fatshttp Server listen on :8888")
    log.Fatal(fasthttp.ListenAndServe(":8888", m))
}
