package dns

import (
	"container-monitor/internal/logger"
	"log"
	"net"

	"github.com/miekg/dns"
)

type Server struct {
	ListenAddr string
	Handler *Handler
}

func NewServer(listenAddr string, proxyIP string, h *Handler) *Server {
	h.ProxyIP = net.ParseIP(proxyIP)
	return &Server{
		ListenAddr: listenAddr,
		Handler: h,
	}
}

func (s *Server) Start() error {
	dns.HandleFunc(".", s.Handler.ServeDNS)
	server := &dns.Server{
		Addr: s.ListenAddr,
		Net: "udp",
	}
	return server.ListenAndServe()
}

func Run(l *logger.Logger) {
	handler := &Handler{Logger: l}
		server := NewServer("10.10.0.1:53", "10.10.0.1", handler)
		if err := server.Start(); err != nil {
			log.Fatalf("dns: %v", err)
		}
}
