# Engine Capability Matrix

Which engine provides each capability, its license, integration model, and the
proprietary Vantage layer that consumes its output. The **Scan Planner** selects
one engine per capability (specialized by application kind); it does not run all
engines against every target.

| Capability | Primary engine(s) | License | Integration | Proprietary layer | Output → |
|---|---|---|---|---|---|
| Crawl (HTTP) | native crawler; katana | first-party; MIT | native; isolated | Attack-surface graph, KnowledgeBase | Observations (endpoints) |
| Crawl (browser/SPA) | katana (headless); Playwright | MIT; Apache-2.0 | isolated; embed | Application model | endpoints, DOM |
| Content discovery | ffuf; feroxbuster | MIT; MIT | isolated | KnowledgeBase | resources |
| JS analysis | native (tree-sitter/Babel) | first-party/MIT | native/embed | endpoint extraction | endpoints, secrets |
| API spec discovery | schemathesis; prism; native | MIT; Apache-2.0 | isolated | API model | endpoints, params |
| Subdomain discovery | subfinder | MIT | isolated | attack surface (DEEP) | hosts |
| HTTP recon | httpx | MIT | isolated | inventory, fingerprint | live hosts |
| DNS analysis | dnsx | MIT | isolated | inventory (DEEP) | records |
| Tech fingerprint | native; wappalyzergo; httpx | first-party; MIT | native; isolated | classification, correlation ctx | technologies |
| TLS analysis | native (cryptography) | Apache/BSD | native | findings | TLS observations |
| Security headers | native | first-party | native | findings | header observations |
| Secret detection | native; gitleaks | first-party; MIT | native; isolated | findings, evidence | secret matches |
| Passive audit | native; ZAP (passive) | first-party; Apache-2.0 | native; isolated | findings | observations |
| Active audit | OWASP ZAP | Apache-2.0 | isolated | validation, correlation | candidates |
| Template checks | Nuclei | MIT | isolated | Template Registry, correlation | candidates |
| API testing (REST) | schemathesis | MIT | isolated | validation | candidates |
| API testing (GraphQL) | graphql-core (native adapter) | MIT | embed | authz analysis | candidates |
| API testing (SOAP) | zeep (native adapter) | MIT | embed | validation | candidates |
| WebSocket | native (websockets) | BSD-3 | native | evidence | ws observations |
| Authorization | native (multi-role) | first-party | native | authz engine | candidates |
| OOB / callback | interactsh; native fallback | MIT; first-party | isolated; native | evidence correlation | interactions |
| Validation | **native validation engine** | first-party | native | — | confidence verdicts |
| Correlation | **native correlation engine** | first-party | native | — | unified findings |
| Risk | **native risk engine** | first-party | native | — | risk scores |
| Reporting | **native** | first-party | native | — | JSON/SARIF/Markdown |

**External (bring-your-own-license):** Burp Suite (PortSwigger, commercial) —
active/passive audit + crawl via the customer's own licensed instance over its
REST API; Vantage ships only the API client.

**Blocked (RED, replacement in use):** trufflehog→gitleaks; sslyze/testssl→native
TLS; wfuzz/dirsearch→ffuf/feroxbuster; whatweb→native+wappalyzergo;
wapiti/w3af→ZAP+Nuclei.

Legend — Integration: `native` = first-party in-process; `embed` = permissive
library in-process; `isolated` = unmodified engine in a sandbox (container or
host binary); `external` = customer-hosted service.
