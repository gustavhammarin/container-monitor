package main

import (
	internaldns "container-monitor/internal/dns"
	"container-monitor/internal/logger"
	"container-monitor/internal/proxy"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	l, err := logger.New("monitor.log")
	if err != nil {
		log.Fatalf("logger: %v", err)
	}
	defer l.Close()

	go func() {
		handler := &internaldns.Handler{Logger: l}
		server := internaldns.NewServer("0.0.0.0:53", "10.10.0.1", handler)
		if err := server.Start(); err != nil {
			log.Fatalf("dns: %v", err)
		}
	}()

	go func() {
		p := proxy.New(l)
		log.Println("Proxy is listening on 0.0.0.0:8080")
		if err := http.ListenAndServe("0.0.0.0:8080", p); err != nil {
			log.Fatalf("proxy: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Turning off...")
}