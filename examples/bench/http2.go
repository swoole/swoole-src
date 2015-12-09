package main

import (
	"flag"
	"fmt"
	"log"
    "runtime"
	"github.com/valyala/fasthttp"
)

var addr = flag.String("addr", ":8080", "TCP address to listen to")

func main() {
    runtime.GOMAXPROCS(runtime.NumCPU() - 1)
	flag.Parse()

	if err := fasthttp.ListenAndServe(*addr, requestHandler); err != nil {
		log.Fatalf("Error in ListenAndServe: %s", err)
	}
}

func requestHandler(ctx *fasthttp.RequestCtx) {
	fmt.Fprintf(ctx, "<h1>\nHello world!\n</h1>\n")
    ctx.SetUserValue("Last-Modified", "Thu, 18 Jun 2015 10:24:27 GMT")
    ctx.SetUserValue("Accept-Ranges", "bytes")
    ctx.SetUserValue("E-Tag", "55829c5b-17")
    ctx.SetUserValue("Server", "golang-http-server")
	ctx.SetContentType("text/html; charset=utf8")
}
