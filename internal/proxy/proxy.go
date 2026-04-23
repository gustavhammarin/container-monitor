package proxy

import (
	"container-monitor/internal/logger"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

type Proxy struct {
	Logger *logger.Logger
}

func New(l *logger.Logger) *Proxy {
	return &Proxy{Logger: l}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	domain := r.Host
	if r.Method == http.MethodConnect {
		p.handleTunnel(w, r, domain)
		return
	}

	p.handleHTTP(w, r, domain)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request, domain string) {
	p.Logger.Write(logger.Entry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Source:    r.RemoteAddr,
		Domain:    domain,
		Method:    r.Method,
		Path:      r.URL.Path,
		Type:      "PROXY_HTTP",
	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (p *Proxy) handleTunnel(w http.ResponseWriter, r *http.Request, domain string) {
	p.Logger.Write(logger.Entry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Source:    r.RemoteAddr,
		Domain:    domain,
		Method:    "CONNECT",
		Path:      r.URL.Path,
		Type:      "PROXY_HTTPS",
	})

	dst, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	defer dst.Close()

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	src, _, err := hijacker.Hijack()
	if err != nil {
		return
	}

	defer src.Close()

	go io.Copy(dst, src)
	io.Copy(src, dst)
}

func Run(l *logger.Logger) {
	p := New(l)
	log.Println("Proxy is listening on 0.0.0.0:8080")
	if err := http.ListenAndServe("0.0.0.0:8080", p); err != nil {
		log.Fatalf("proxy: %v", err)
	}
}
