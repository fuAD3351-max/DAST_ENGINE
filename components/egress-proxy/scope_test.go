package main

import "testing"

func rule(kind, host string, schemes []string, prefix string) ScopeRule {
	return ScopeRule{Kind: kind, Host: host, Schemes: schemes, PathPrefix: prefix}
}

func TestUnauthorizedDeniesEverything(t *testing.T) {
	e := NewScopeEngine([]ScopeRule{rule("include", "app.example.com", nil, "/")}, false)
	if e.Allows("https://app.example.com/", "GET") {
		t.Fatal("unauthorized target must deny")
	}
}

func TestIncludeAndExclude(t *testing.T) {
	rules := []ScopeRule{
		rule("include", "app.example.com", nil, "/"),
		rule("exclude", "app.example.com", nil, "/admin"),
	}
	e := NewScopeEngine(rules, true)
	if !e.Allows("https://app.example.com/x", "GET") {
		t.Fatal("in-scope path should be allowed")
	}
	if e.Allows("https://app.example.com/admin/panel", "GET") {
		t.Fatal("excluded path should be denied")
	}
}

func TestExcludeBeatsIncludeOrderIndependent(t *testing.T) {
	rules := []ScopeRule{
		rule("exclude", "app.example.com", nil, "/admin"),
		rule("include", "app.example.com", nil, "/"),
	}
	e := NewScopeEngine(rules, true)
	if e.Allows("https://app.example.com/admin", "GET") {
		t.Fatal("exclude must win regardless of order")
	}
}

func TestOutOfScopeHostDenied(t *testing.T) {
	e := NewScopeEngine([]ScopeRule{rule("include", "app.example.com", nil, "/")}, true)
	if e.Allows("https://evil.example.com/", "GET") {
		t.Fatal("out-of-scope host must be denied")
	}
}

func TestWildcardSubdomain(t *testing.T) {
	e := NewScopeEngine([]ScopeRule{rule("include", "*.example.com", nil, "/")}, true)
	if !e.Allows("https://api.example.com/", "GET") {
		t.Fatal("subdomain should match wildcard")
	}
	if e.Allows("https://example.com/", "GET") {
		t.Fatal("apex must not match *.example.com")
	}
}

func TestPrivateAddressBlockedWithoutOptIn(t *testing.T) {
	e := NewScopeEngine([]ScopeRule{rule("include", "app.example.com", nil, "/")}, true)
	if e.Allows("https://127.0.0.1/", "GET") || e.Allows("https://10.0.0.5/", "GET") {
		t.Fatal("private literals must be blocked without opt-in")
	}
}

func TestPrivateAddressAllowedWithCIDR(t *testing.T) {
	e := NewScopeEngine([]ScopeRule{{Kind: "include", Host: "10.0.0.0/8", Schemes: []string{"https"}, PathPrefix: "/"}}, true)
	if !e.Allows("https://10.0.0.5/", "GET") {
		t.Fatal("explicit CIDR should allow private address")
	}
}

func TestSchemeEnforced(t *testing.T) {
	e := NewScopeEngine([]ScopeRule{rule("include", "app.example.com", []string{"https"}, "/")}, true)
	if e.Allows("http://app.example.com/", "GET") {
		t.Fatal("scheme not in rule must be denied")
	}
}

func TestDefaultPortOnly(t *testing.T) {
	e := NewScopeEngine([]ScopeRule{rule("include", "app.example.com", []string{"https"}, "/")}, true)
	if e.Allows("https://app.example.com:8443/", "GET") {
		t.Fatal("non-default port without explicit ports rule must be denied")
	}
}
