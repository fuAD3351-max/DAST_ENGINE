// Vantage egress proxy — a standard-library-only, scope-enforcing forward proxy.
// Engines route all egress through it; it re-checks every request against the
// same scope-rule contract the Python ScopeEngine uses (contracts/scope-rule).
module github.com/vantage-dast/egress-proxy

go 1.24
