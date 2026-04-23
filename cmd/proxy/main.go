package main

import (
	"container-monitor/internal/logger"
	"container-monitor/internal/proxy"
	"log"
	"net/http"
)

func main(){
	l, err := logger.New("proxy_requests.log")
	if err != nil {
		log.Fatalf("logger: %v", err)
	}
	defer l.Close()

	p := proxy.New(l)

	log.Println("Proxy listening on 0.0.0.0:8080")
	if err := http.ListenAndServe("0.0.0.0:8080", p); err != nil {
		log.Fatalf("proxy: %v", err)
	}
}