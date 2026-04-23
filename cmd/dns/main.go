package main

import (
	"container-monitor/internal/dns"
	"container-monitor/internal/logger"
	"log"
)

func main() {
	l, err := logger.New("dns_queries.log")
	if err != nil {
		log.Fatalf("logger: %v", err)
	}
	defer l.Close()

	handler := &dns.Handler{Logger: l}
	server := dns.NewServer("0.0.0.0:53", "10.10.0.1", handler)

	if err := server.Start(); err != nil {
		log.Fatalf("server: %v", err)
	}
}