// Vantage egress proxy — a scope-enforcing HTTP/HTTPS forward proxy.
//
// Engines run with HTTP_PROXY/HTTPS_PROXY pointed at this process. Every request
// (including the CONNECT target for TLS) is checked against the scope rules; a
// request outside scope is refused with 403 and never forwarded. This gives the
// same scope guarantee to containerized/native engines that the native Python
// engines get from the in-process ScopedHttpClient.
//
// Scope rules are loaded from a JSON file matching contracts/scope-rule.schema
// (an array of ScopeRule), given by -rules. Authorization is asserted by the
// orchestrator that launches the proxy (-authorized, default true).
//
// Standard library only — no external dependencies.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

type config struct {
	addr       string
	rulesPath  string
	authorized bool
}

func loadRules(path string) ([]ScopeRule, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-provided path
	if err != nil {
		return nil, err
	}
	var rules []ScopeRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

type proxy struct {
	scope     *ScopeEngine
	transport *http.Transport
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	target := r.URL.String()
	if d := p.scope.Check(target, r.Method); !d.Allowed {
		http.Error(w, "out of scope: "+d.Reason, http.StatusForbidden)
		log.Printf("DENY %s %s (%s)", r.Method, target, d.Reason)
		return
	}
	r.RequestURI = ""
	resp, err := p.transport.RoundTrip(r)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// For HTTPS the URL is host:port; scope-check it as an https origin.
	host := r.Host
	if d := p.scope.Check("https://"+host+"/", ""); !d.Allowed {
		http.Error(w, "out of scope: "+d.Reason, http.StatusForbidden)
		log.Printf("DENY CONNECT %s (%s)", host, d.Reason)
		return
	}
	upstream, err := net.DialTimeout("tcp", host, 15*time.Second)
	if err != nil {
		http.Error(w, "upstream dial failed", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		upstream.Close()
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go pipe(upstream, client)
	go pipe(client, upstream)
}

func pipe(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}

func main() {
	cfg := config{}
	flag.StringVar(&cfg.addr, "addr", "127.0.0.1:8081", "listen address")
	flag.StringVar(&cfg.rulesPath, "rules", "", "path to scope-rules JSON (contracts/scope-rule)")
	flag.BoolVar(&cfg.authorized, "authorized", true, "target authorization already verified")
	flag.Parse()

	if cfg.rulesPath == "" {
		log.Fatal("-rules is required (a JSON array of scope rules)")
	}
	rules, err := loadRules(cfg.rulesPath)
	if err != nil {
		log.Fatalf("loading rules: %v", err)
	}
	p := &proxy{
		scope:     NewScopeEngine(rules, cfg.authorized),
		transport: &http.Transport{Proxy: nil, DisableKeepAlives: false},
	}
	log.Printf("vantage egress proxy on %s enforcing %d scope rule(s)", cfg.addr, len(rules))
	srv := &http.Server{Addr: cfg.addr, Handler: p, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
