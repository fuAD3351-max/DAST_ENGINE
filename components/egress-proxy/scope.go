// Package main implements Vantage's scope-enforcing egress proxy.
//
// This is the Go counterpart to the Python ScopeEngine. Both consume the same
// scope-rule contract (contracts/scope-rule.schema.json), so the enforcement
// semantics match across languages: excludes beat includes, nothing outside the
// include set is allowed, and private/loopback address literals are refused
// unless a rule opts into them. Keeping this in Go lets it sit on the hot path
// (every engine's traffic) with minimal overhead and no runtime dependencies.
package main

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

// ScopeRule mirrors contracts/scope-rule.schema.json.
type ScopeRule struct {
	Kind       string   `json:"kind"`        // "include" | "exclude"
	Host       string   `json:"host"`        // exact, *.wildcard, IP, or CIDR
	Schemes    []string `json:"schemes"`     // http/https/ws/wss
	Ports      []int    `json:"ports"`       // nil => default port for scheme only
	PathPrefix string   `json:"path_prefix"` // must start with /
	PathRegex  *string  `json:"path_regex"`
	Methods    []string `json:"methods"` // nil => any
}

// Decision is the result of a scope check.
type Decision struct {
	Allowed bool
	Reason  string
	Rule    int
}

var defaultPorts = map[string]int{"http": 80, "https": 443, "ws": 80, "wss": 443}

// ScopeEngine enforces a set of rules. Construct with NewScopeEngine.
type ScopeEngine struct {
	rules        []ScopeRule
	authorized   bool
	privateOptIn bool
	regexCache   map[string]*regexp.Regexp
}

// NewScopeEngine builds an engine from rules. authorized should reflect that the
// orchestrator already verified the target's authorization before dispatch.
func NewScopeEngine(rules []ScopeRule, authorized bool) *ScopeEngine {
	e := &ScopeEngine{rules: rules, authorized: authorized, regexCache: map[string]*regexp.Regexp{}}
	for _, r := range rules {
		if ruleAllowsPrivate(r) {
			e.privateOptIn = true
		}
	}
	return e
}

type parsedURL struct {
	scheme string
	host   string
	port   int
	path   string
	method string
}

func parseURL(raw, method string) (parsedURL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return parsedURL{}, false
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	port := 0
	if p := u.Port(); p != "" {
		n, err := net.LookupPort("tcp", p)
		if err != nil {
			return parsedURL{}, false
		}
		port = n
	} else if dp, ok := defaultPorts[scheme]; ok {
		port = dp
	}
	if port == 0 {
		return parsedURL{}, false
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	m := ""
	if method != "" {
		m = strings.ToUpper(method)
	}
	return parsedURL{scheme, host, port, path, m}, true
}

func isPrivateLiteral(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

func ruleAllowsPrivate(r ScopeRule) bool {
	return isPrivateLiteral(r.Host) || strings.Contains(r.Host, "/")
}

func hostMatches(ruleHost, host string) bool {
	if ruleHost == host {
		return true
	}
	if strings.HasPrefix(ruleHost, "*.") {
		suffix := ruleHost[1:] // ".example.com"
		return strings.HasSuffix(host, suffix) && host != suffix[1:]
	}
	addr := net.ParseIP(host)
	if addr == nil {
		return false
	}
	if strings.Contains(ruleHost, "/") {
		_, cidr, err := net.ParseCIDR(ruleHost)
		if err != nil {
			return false
		}
		return cidr.Contains(addr)
	}
	ruleIP := net.ParseIP(ruleHost)
	return ruleIP != nil && ruleIP.Equal(addr)
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func (e *ScopeEngine) ruleMatches(r ScopeRule, u parsedURL) bool {
	schemes := r.Schemes
	if len(schemes) == 0 {
		schemes = []string{"https", "http"}
	}
	if !containsStr(schemes, u.scheme) {
		return false
	}
	if !hostMatches(r.Host, u.host) {
		return false
	}
	if r.Ports != nil {
		if !containsInt(r.Ports, u.port) {
			return false
		}
	} else if u.port != defaultPorts[u.scheme] {
		return false
	}
	prefix := r.PathPrefix
	if prefix == "" {
		prefix = "/"
	}
	if !strings.HasPrefix(u.path, prefix) {
		return false
	}
	if r.PathRegex != nil {
		re := e.regexCache[*r.PathRegex]
		if re == nil {
			c, err := regexp.Compile(*r.PathRegex)
			if err != nil {
				return false
			}
			re = c
			e.regexCache[*r.PathRegex] = c
		}
		if !re.MatchString(u.path) {
			return false
		}
	}
	if r.Methods != nil && u.method != "" && !containsStr(r.Methods, u.method) {
		return false
	}
	return true
}

// Check decides whether a URL+method is in scope.
func (e *ScopeEngine) Check(rawURL, method string) Decision {
	if !e.authorized {
		return Decision{false, "target has no valid authorization record", -1}
	}
	u, ok := parseURL(rawURL, method)
	if !ok {
		return Decision{false, "unparseable or portless url", -1}
	}
	if isPrivateLiteral(u.host) && !e.privateOptIn {
		return Decision{false, "private/loopback address not explicitly in scope", -1}
	}
	for i, r := range e.rules {
		if strings.ToLower(r.Kind) == "exclude" && e.ruleMatches(r, u) {
			return Decision{false, "excluded by rule", i}
		}
	}
	for i, r := range e.rules {
		if strings.ToLower(r.Kind) != "exclude" && e.ruleMatches(r, u) {
			return Decision{true, "included by rule", i}
		}
	}
	return Decision{false, "not covered by any include rule", -1}
}

// Allows is a boolean convenience over Check.
func (e *ScopeEngine) Allows(rawURL, method string) bool {
	return e.Check(rawURL, method).Allowed
}
