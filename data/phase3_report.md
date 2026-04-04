# Attack Surface Analysis Report

**Target:** `http://testfire.net/`  
**Report Date:** 2026-04-04  
**Phase:** Phase 3 — Reconnaissance-Based Analysis  
**Analyzer Version:** 1.0

> **Disclaimer:** This report is based exclusively on passive and active
> reconnaissance data collected during Phase 1. All findings represent
> *initial attack surface indicators* only. No exploitation or vulnerability
> confirmation has been performed. All observations require further
> validation before drawing definitive security conclusions.

---

## 1. Target Information

| Field | Value |
|-------|-------|
| Target URL | `http://testfire.net/` |
| Domain | `testfire.net` |
| IP Address(es) | `65.61.137.117` |
| Collection Timestamp | 2026-04-04T07:21:36 |
| Registrar | Amazon Registrar, Inc. |
| Domain Created | 1999-07-23 13:52:32 |
| Domain Expires | 2026-07-23 13:52:32 |
| Registered Country | GB |
| Name Servers (WHOIS) | ASIA3.AKAM.NET, EUR2.AKAM.NET, EUR5.AKAM.NET, NS1-206.AKAM.NET |
| Organization (Shodan) | Rackspace Backbone Engineering / Rackspace Hosting (Dallas, United States) |

**Scope:** Reconnaissance-only analysis of the target domain and associated observed infrastructure. No active exploitation performed.

**Data Collection Limitations Recorded:** None.

---

## 2. Phase 1 Reconnaissance Summary

### 2.1 DNS / IP Information

| Record Type | Value |
|------------|-------|
| IP Address(es) | 65.61.137.117 |
| A | 65.61.137.117 |
| AAAA | Not observed |
| MX | Not observed |
| NS | eur5.akam.net., usw2.akam.net., ns1-99.akam.net., usc3.akam.net., eur2.akam.net., asia3.akam.net., ns1-206.akam.net., usc2.akam.net. |
| TXT | "v=spf1 mx/24 -all" |
| CNAME | Not observed |

### 2.2 Subdomain Enumeration

Total observed: **8**

| Subdomain | IP | Discovery Source |
|-----------|-----|------------------|
| `www.testfire.net` | 65.61.137.117 | dns_bruteforce |
| `demo.testfire.net` | 65.61.137.117 | dns_bruteforce |
| `localhost.testfire.net` | 65.61.137.117 | dns_bruteforce |
| `ftp.testfire.net` | 65.61.137.117 | dns_bruteforce |
| `testfire.net` | N/A | amass |
| `demo2.testfire.net` | N/A | subfinder |
| `evil.testfire.net` | N/A | subfinder |
| `altoro.testfire.net` | N/A | subfinder |

### 2.3 Open Ports / Services

Total observed (Nmap: 3, Shodan: 3, deduplicated: **3**)

| Port | Service | Version | Sources |
|------|---------|---------|---------|
| 80 | http | N/A | kali_nmap, shodan |
| 443 | https | N/A | kali_nmap, shodan |
| 8080 | http-proxy | N/A | kali_nmap, shodan |

### 2.4 HTTP Response Headers

- **HTTP Available:** True
- **HTTPS Available:** True
- **HTTP Status Code:** 200
- **Redirects:** None

**Observed response headers:**

| Header | Value |
|--------|-------|
| `Server` | `Apache-Coyote/1.1` |
| `Content-Type` | `text/html;charset=ISO-8859-1` |
| `Set-Cookie` | `JSESSIONID=711E43CA52835EA17E14E18C2ECDAF12; Path=/; HttpOnly` |

### 2.5 SSL/TLS Certificate

| Field | Value |
|-------|-------|
| Subject | demo.testfire.net |
| Issuer | Sectigo Limited |
| Protocol | TLS |
| Valid From | May 21 00:00:00 2025 GMT |
| Expiry | Jun 21 23:59:59 2026 GMT -- Warning: 78 days remaining |
| Subject Alternative Names | demo.testfire.net |

### 2.6 Technology Fingerprint

- **Server:** Apache-Coyote/1.1
- **CMS:** Not observed
- **Frameworks:** Apache, Java
- **Libraries:** Not observed

**WhatWeb Results (technology identifiers only):**

| Component | Version |
|-----------|---------|
| Apache | N/A |
| Java | N/A |

**Security Headers Status (passive recon):**

| Header | Status |
|--------|--------|
| Strict-Transport-Security | Not observed |
| Content-Security-Policy | Not observed |
| X-Frame-Options | Not observed |
| X-Content-Type-Options | Not observed |
| Referrer-Policy | Not observed |
| Permissions-Policy | Not observed |
| X-XSS-Protection | Not observed |

### 2.7 HTTP Methods

Observed allowed HTTP methods: Not available in Phase 1 data.

### 2.8 URLs / Endpoints / Forms / Parameters

**Asset Summary:**

| Asset Type | Count |
|------------|-------|
| Crawled URLs | 13 |
| HTML Forms | 5 |
| URL / Form Parameters | 9 |
| Notable Endpoints | 2 |
| JavaScript Endpoints | 0 |
| Hidden Endpoints (ffuf) | 2 |
| Wayback Machine URLs | 253 |

**Crawled URLs:**

- `http://testfire.net`
- `http://testfire.net/index.jsp`
- `http://testfire.net/default.jsp?content=security.htm`
- `http://testfire.net/status_check.jsp`
- `http://testfire.net/survey_questions.jsp`
- `http://testfire.net/login.jsp`
- `http://testfire.net/subscribe.jsp`
- `http://testfire.net/feedback.jsp`
- `http://testfire.net/swagger/index.html`
- `http://testfire.net/sendFeedback`
- `http://testfire.net/doSubscribe`
- `http://testfire.net/search.jsp`
- `http://testfire.net/doLogin`

**Notable Endpoints:**

| URL | Category | Method | Source |
|-----|----------|--------|--------|
| `http://testfire.net/search.jsp` | search | GET | form |
| `http://testfire.net/login.jsp` | login | GET | crawl |

**Hidden Endpoints (directory fuzzing):**

| Path | HTTP Status | Source |
|------|-------------|--------|
| `http://testfire.net/admin/` | 302 | kali_ffuf |
| `http://testfire.net/admin` | 302 | kali_ffuf |

**HTML Forms Observed:**

| Page | Form Action | Method | Inputs |
|------|-------------|--------|--------|
| `http://testfire.net` | `http://testfire.net/search.jsp` | GET | query |
| `http://testfire.net/status_check.jsp` | `javascript:checkSiteStatus('AltoroMutual')` | GET | - |
| `http://testfire.net/login.jsp` | `http://testfire.net/doLogin` | POST | uid, passw |
| `http://testfire.net/subscribe.jsp` | `http://testfire.net/doSubscribe` | POST | txtEmail |
| `http://testfire.net/feedback.jsp` | `http://testfire.net/sendFeedback` | POST | name, email_addr, subject, comments |

**URL / Form Parameters Observed:**

| Parameter | Source | Method |
|-----------|--------|--------|
| `query` | form | GET |
| `content` | url | N/A |
| `uid` | form | POST |
| `passw` | form | POST |
| `txtEmail` | form | POST |
| `name` | form | POST |
| `email_addr` | form | POST |
| `subject` | form | POST |
| `comments` | form | POST |

**Wayback Machine:** 253 historical URL(s) observed. Refer to `phase1_canonical.json` for full list.

### 2.9 Cookie Analysis

| Cookie Name | Secure | HttpOnly | SameSite |
|-------------|--------|----------|----------|
| `JSESSIONID` | No | Yes | Not set |

### 2.10 WAF Detection

**WAF Detected:** Not detected (source: kali_wafw00f)

> Note: WAF absence is an initial indicator only. Requires further validation.

### 2.11 Tool Sources

| Component | Source |
|-----------|--------|
| `banner` | `socket` |
| `ffuf` | `kali_ffuf` |
| `nmap_tcp` | `kali_nmap` |
| `syn_scan` | `kali_nmap_connect` |
| `wafw00f` | `kali_wafw00f` |

---

## 3. Attack Surface Analysis

> All items in this section are **initial attack surface indicators** derived from reconnaissance data only.
> None of the following constitutes a confirmed vulnerability. All require further validation.

### 3.1 Attack Surface Metrics

| Metric | Value |
|--------|-------|
| Open Ports | 3 |
| Subdomains | 8 |
| Crawled URLs | 13 |
| HTML Forms | 5 |
| URL Parameters | 9 |
| Notable Endpoints | 2 |
| Hidden Endpoints | 2 |
| Wayback URLs | 253 |
| WAF Detected | No |
| SSL Valid | Yes |
| Missing Security Headers | Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection |

### 3.2 Detailed Findings

#### Banner Disclosure

**F004** [LOW] -- Follow-up Priority: Low

- **Observation:** Server header observed in HTTP response (source: active_recon.headers.Server): 'Apache-Coyote/1.1'.
- **Recommended Next Check:** Determine whether server version string should be suppressed in production configuration.

**F005** [LOW] -- Follow-up Priority: Low

- **Observation:** Service banner containing server identity observed on port 8080 (http-proxy) (source: active_recon.banners).
- **Recommended Next Check:** Review and consider suppressing banner content on port 8080.

**F006** [LOW] -- Follow-up Priority: Low

- **Observation:** Service banner containing server identity observed on port 80 (http) (source: active_recon.banners).
- **Recommended Next Check:** Review and consider suppressing banner content on port 80.

#### Cookie Security

**F007** [MEDIUM] -- Follow-up Priority: Medium

- **Observation:** Cookie 'JSESSIONID' (source: active_recon.cookies_analysis) observed with potential configuration concerns: Secure flag not observed (cookie may transmit over plaintext HTTP); SameSite attribute not observed (cross-site request concern — requires validation).
- **Recommended Next Check:** Validate cookie 'JSESSIONID' attributes during authenticated session testing. Confirm cookie role before drawing conclusions.

#### Dns Email

**F030** [INFO] -- Follow-up Priority: -

- **Observation:** SPF TXT record observed (source: passive_recon.dns_records.TXT): "v=spf1 mx/24 -all".
- **Recommended Next Check:** Validate SPF policy strictness. Also check DMARC and DKIM records.

#### Form Analysis

**F020** [LOW] -- Follow-up Priority: Low

- **Observation:** Hidden field 'cfile' (value: 'comments.txt') observed in form 'http://testfire.net/sendFeedback' (source: active_recon.crawl.hidden_fields).
- **Recommended Next Check:** Inspect hidden field 'cfile' for business logic implications during authorized testing.

**F021** [MEDIUM] -- Follow-up Priority: High

- **Observation:** Authentication form observed (action: 'http://testfire.net/doLogin', method: POST, inputs: ['uid', 'passw']). No CSRF token observed -- requires further validation.
- **Recommended Next Check:** Verify authentication security: session handling, HTTPS, and CSRF protection.

**F022** [INFO] -- Follow-up Priority: Low

- **Observation:** 4 standard HTML forms observed (actions: http://testfire.net/search.jsp, javascript:checkSiteStatus('AltoroMutual'), http://testfire.net/doSubscribe, http://testfire.net/sendFeedback). None appear to be authentication or file upload forms.
- **Recommended Next Check:** Inspect form inputs for potential injection points during authorized testing.

#### Hidden Endpoints

**F018** [MEDIUM] -- Follow-up Priority: High

- **Observation:** Path 'http://testfire.net/admin/' responded with HTTP 302 during directory fuzzing (source: kali_ffuf -> active_recon.hidden_endpoints).
- **Recommended Next Check:** Verify authentication and access control for 'http://testfire.net/admin/'.

**F019** [MEDIUM] -- Follow-up Priority: High

- **Observation:** Path 'http://testfire.net/admin' responded with HTTP 302 during directory fuzzing (source: kali_ffuf -> active_recon.hidden_endpoints).
- **Recommended Next Check:** Verify authentication and access control for 'http://testfire.net/admin'.

#### Http Methods

**F011** [INFO] -- Follow-up Priority: Low

- **Observation:** HTTP methods data not available in Phase 1 data (active_recon.http_methods is empty).
- **Recommended Next Check:** Verify allowed HTTP methods through direct testing.

#### Port Exposure

**F008** [INFO] -- Follow-up Priority: Low

- **Observation:** 3 open port(s) observed (sources: Nmap + Shodan, deduplicated): [80, 443, 8080]. Services: 80/http, 443/https, 8080/http-proxy.
- **Recommended Next Check:** Verify service versions and whether all open ports are intentionally exposed.

**F009** [MEDIUM] -- Follow-up Priority: Medium

- **Observation:** Non-standard HTTP port 8080 (http-proxy) observed as open (source: kali_nmap, shodan). May indicate an additional web interface or management service.
- **Recommended Next Check:** Determine whether port 8080 exposes an alternate entry point or admin interface.

#### Robots Sitemap

**F025** [INFO] -- Follow-up Priority: -

- **Observation:** robots.txt returned HTTP 404 (source: active_recon.discovery.robots.status).
- **Recommended Next Check:** Confirm robots.txt is intentionally absent or verify URL path.

**F026** [INFO] -- Follow-up Priority: -

- **Observation:** No sitemap data observed (source: active_recon.discovery.sitemap_urls and robots.sitemaps are empty).
- **Recommended Next Check:** Check for sitemap.xml at common paths.

#### Security Headers

**F003** [MEDIUM] -- Follow-up Priority: Medium

- **Observation:** The following security headers were not observed in HTTP response (source: active_recon.headers / passive_recon.technology.security_headers): Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection.
- **Recommended Next Check:** Configure missing security headers at the web server or application layer.

#### Sensitive Endpoints

**F012** [MEDIUM] -- Follow-up Priority: High

- **Observation:** Endpoint category 'administrative' observed (1 URL(s), sources: hidden_endpoints): 'http://testfire.net/admin/'.
- **Recommended Next Check:** Verify authentication and access control requirements for 'administrative' endpoints.

**F013** [MEDIUM] -- Follow-up Priority: Medium

- **Observation:** Endpoint category 'api_docs' observed (1 URL(s), sources: crawl): 'http://testfire.net/swagger/index.html'.
- **Recommended Next Check:** Verify authentication and access control requirements for 'api_docs' endpoints.

**F014** [MEDIUM] -- Follow-up Priority: High

- **Observation:** Endpoint category 'authentication' observed (2 URL(s), sources: crawl, notable_endpoints): 'http://testfire.net/doLogin', 'http://testfire.net/login.jsp'.
- **Recommended Next Check:** Verify authentication and access control requirements for 'authentication' endpoints.

**F015** [LOW] -- Follow-up Priority: Medium

- **Observation:** Endpoint category 'feedback' observed (1 URL(s), sources: crawl): 'http://testfire.net/feedback.jsp'.
- **Recommended Next Check:** Verify authentication and access control requirements for 'feedback' endpoints.

**F016** [LOW] -- Follow-up Priority: Medium

- **Observation:** Endpoint category 'search' observed (1 URL(s), sources: crawl, notable_endpoints): 'http://testfire.net/search.jsp'.
- **Recommended Next Check:** Verify authentication and access control requirements for 'search' endpoints.

#### Ssl Tls

**F001** [MEDIUM] -- Follow-up Priority: Medium

- **Observation:** SSL/TLS certificate observed with 78 day(s) remaining until expiry (issuer: Sectigo Limited). Below recommended threshold of 90 days.
- **Recommended Next Check:** Plan certificate renewal to ensure continuous availability.

**F002** [INFO] -- Follow-up Priority: Low

- **Observation:** Observed SSL/TLS configuration: protocol=TLS, SAN=demo.testfire.net.
- **Recommended Next Check:** Validate SAN entries and TLS protocol version support.

#### Subdomain Exposure

**F023** [INFO] -- Follow-up Priority: Low

- **Observation:** 8 subdomain(s) observed (source: passive_recon.subdomains): www.testfire.net, demo.testfire.net, localhost.testfire.net, ftp.testfire.net, testfire.net, demo2.testfire.net, evil.testfire.net, altoro.testfire.net.
- **Recommended Next Check:** Verify active status and service configuration of each subdomain.

**F024** [MEDIUM] -- Follow-up Priority: Medium

- **Observation:** Subdomains with notable naming patterns observed: localhost.testfire.net, ftp.testfire.net, evil.testfire.net. May indicate development, administrative, FTP, or legacy services.
- **Recommended Next Check:** Review access controls and service exposure for flagged subdomains.

#### Technology Fingerprint

**F029** [LOW] -- Follow-up Priority: Low

- **Observation:** Technology stack identified from reconnaissance (source: passive_recon.technology): Server: Apache-Coyote/1.1; Frameworks: Apache, Java.
- **Recommended Next Check:** Cross-reference identified components against known vulnerability databases.

#### Url Parameters

**F027** [INFO] -- Follow-up Priority: Medium

- **Observation:** 9 URL/form parameter(s) observed (source: active_recon.crawl.params): query, content, uid, passw, txtEmail, name, email_addr, subject, comments.
- **Recommended Next Check:** Validate parameters for injection susceptibility during authorized testing.

**F028** [MEDIUM] -- Follow-up Priority: High

- **Observation:** Parameter(s) with naming patterns associated with path/URL manipulation observed: content. This is a potential risk indicator requiring further validation.
- **Recommended Next Check:** Investigate parameter behavior and validate input handling.

#### Waf Detection

**F010** [LOW] -- Follow-up Priority: Low

- **Observation:** No Web Application Firewall (WAF) detected during Phase 1 reconnaissance (source: kali_wafw00f). This is an observed indicator only — requires further validation.
- **Recommended Next Check:** Confirm WAF configuration using additional reconnaissance techniques.

#### Wayback Disclosure

**F017** [MEDIUM] -- Follow-up Priority: Medium

- **Observation:** 24 URL(s) with potentially sensitive file extensions observed in Wayback Machine historical data (source: passive_recon.wayback.urls). Sample: http://testfire.net/admin/clients.xls, http://testfire.net:80/bank/account.aspx.cs, http://testfire.net:80/bank/apply.aspx.cs, http://testfire.net:80/bank/bank.master.cs, http://testfire.net:80/bank/customize.aspx.cs.
- **Recommended Next Check:** Check current accessibility of historical URLs with sensitive extensions.


---

## 4. Executive Summary

**Target:** `http://testfire.net/` | **Date:** 2026-04-04

| Category | Count | Risk Distribution | Count |
|----------|-------|--------------------|-------|
| Subdomains | 8 | High | 0 |
| Open Ports (Nmap: 3, Shodan: 3, deduplicated: 3) | 3 | Medium | 13 |
| Crawled URLs | 13 | Low | 8 |
| Forms | 5 | Informational | 9 |
| Hidden Endpoints | 2 | | |

> **Certificate Expiry (Warning):** SSL/TLS certificate observed with only **78 day(s)** remaining until expiry (source: passive_recon.ssl.days_remaining).

Based on the analysis of collected reconnaissance data, the following areas were identified as initial attack surface indicators: authentication-related endpoints, services on non-standard ports, 7 absent HTTP security header(s), SSL/TLS certificate with 78 day(s) remaining until expiry, no WAF coverage confirmed during reconnaissance, subdomains with notable naming patterns, and historical URLs with potentially sensitive file types. All findings are *observed configuration indicators* only and require further validation in an authorized testing environment.

---

## 5. Recommended Next Steps

> All actions require explicit authorization.

### 5.1 High Priority

- **Sensitive Endpoints:** Verify authentication and access control requirements for 'administrative' endpoints.
- **Sensitive Endpoints:** Verify authentication and access control requirements for 'authentication' endpoints.
- **Hidden Endpoints:** Verify authentication and access control for 'http://testfire.net/admin/'.
- **Hidden Endpoints:** Verify authentication and access control for 'http://testfire.net/admin'.
- **Form Analysis:** Verify authentication security: session handling, HTTPS, and CSRF protection.

*+ 1 additional high-priority items*


### 5.2 Medium Priority

- **Ssl Tls:** Plan certificate renewal to ensure continuous availability.
- **Security Headers:** Configure missing security headers at the web server or application layer.
- **Cookie Security:** Validate cookie 'JSESSIONID' attributes during authenticated session testing. Confirm cookie role before drawing conclusions.
- **Port Exposure:** Determine whether port 8080 exposes an alternate entry point or admin interface.
- **Sensitive Endpoints:** Verify authentication and access control requirements for 'api_docs' endpoints.

*+ 5 additional medium-priority items*

---

*Standard testing areas for subsequent phases: authentication endpoints, 
input parameters, security headers, SSL/TLS configuration, and access controls.*

---

## 6. Limitations

This report is subject to the following limitations:

1. **Reconnaissance-only scope:** All findings are based on passive and active
   reconnaissance data collected in Phase 1. No active exploitation,
   authenticated testing, or vulnerability scanning has been performed.

2. **No vulnerability confirmation:** Observations represent *observed
   configuration* and *initial attack surface indicators* only. The presence
   of a configuration item does not confirm the existence of an exploitable
   vulnerability.

3. **Data completeness:** Some tools may have returned partial or no data due
   to network restrictions, tool availability, or target configuration.
   Where data is unavailable, the report notes `Not available in Phase 1 data`
   or `Not observed`.

4. **Time-bound data:** Reconnaissance data reflects the state of the target
   at the time of Phase 1 collection. Infrastructure and configuration changes
   may have occurred since then.

5. **Authorization boundary:** This analysis was conducted within the scope of
   an authorized academic exercise. No unauthorized access was attempted.

6. **No exploit steps:** This report contains no exploitation guidance. All
   recommended next steps require explicit authorization prior to execution.

---
*Report generated by Phase 3 Analysis System v1.0 -- 2026-04-04 00:21 UTC*  
*For academic use only.*