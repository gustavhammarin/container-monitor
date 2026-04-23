package dns

import (
	"fmt"
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
	fmt.Printf("DNS is listening on %s\n", s.ListenAddr)
	return server.ListenAndServe()
}