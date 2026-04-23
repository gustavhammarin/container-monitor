package dns

import (
	"container-monitor/internal/logger"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Handler struct{
	Logger *logger.Logger
	ProxyIP net.IP
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		domain := strings.TrimSuffix(q.Name, ".")

		h.Logger.Write(logger.Entry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Source: w.RemoteAddr().String(),
			Domain: domain,
			QueryType: dns.TypeToString[q.Qtype],
			Type: "DNS",
		})

		if q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name: q.Name,
					Rrtype: dns.TypeA,
					Class: dns.ClassINET,
					Ttl: 60,
				},
				A:   h.ProxyIP,
			})
		}
	}

	w.WriteMsg(m)
}