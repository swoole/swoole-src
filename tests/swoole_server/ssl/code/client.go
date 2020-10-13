package main

import (
    "crypto/tls"
    "fmt"
    "io"
	"log"
	"os"
)

func main() {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	url := fmt.Sprintf("127.0.0.1:%s", os.Args[1]);
	   
    conn, err := tls.Dial("tcp", url, conf)
    if err != nil {
        log.Fatalln(err.Error())
    }

    buf := make([]byte, 1024)

	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	if err != nil {
		log.Fatalln(err.Error())
	}
	len, err := conn.Read(buf)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println("Receive From Server:", string(buf[:len]))
	}
}
