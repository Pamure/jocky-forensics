# CDN, Domain Fronting & Traffic Routing Security: Research Report

## Context: SIH26148 — Central Management Interface & Traffic Routing

## 1. CDN Architecture & Traffic Routing

Modern CDNs handle globally distributed traffic while maintaining cryptographic privacy and multi-layered security.

### Cloudflare — Pure Anycast BGP Model
Cloudflare's architecture is built entirely around a globally distributed Anycast BGP network. Every PoP announces the same IP address prefixes to the internet. BGP routing naturally steers packets to the closest PoP. If a PoP goes down, BGP withdraws routes and upstream ISPs re-route traffic within milliseconds. Cloudflare Workers run natively inside every Anycast node.

### AWS CloudFront & Route 53
AWS pairs Route 53 (globally distributed DNS) with CloudFront (traditional Unicast/Anycast hybrid). Route 53 evaluates policies (Latency, Geolocation, Weighted) to return optimal endpoints. Lambda@Edge and CloudFront Functions execute code at regional edge caches.

### Azure Front Door
Microsoft Azure routes traffic via Azure Front Door (Layer 7 CDN) and Traffic Manager (DNS-based). Front Door uses Anycast to pull traffic into nearest PoP, then transitions onto Microsoft's private global WAN network ("Cold Potato Routing").

### Fastly — High-Capacity POPs with Wasm Edge
Fastly engineered around fewer, hyper-connected PoPs with massive RAM. Instant Purge achieves global cache invalidation in under 150ms. Fastly Compute uses WebAssembly sandboxes for edge logic.

## 2. TLS, SNI, and the Privacy Evolution

### Server Name Indication (SNI)
The client includes the hostname in plaintext inside the SNI extension of TLS ClientHello. Problem: passive observers (ISPs, firewalls, censors) can inspect which website a user visits.

### Encrypted Client Hello (ECH) — RFC 9849
ECH encrypts the sensitive inner portions of ClientHello including the actual target SNI using Hybrid Public Key Encryption (HPKE).

```
Client → CDN Edge: Outer ClientHello (cleartext SNI: cdn-provider.com)
Client → CDN Edge: Inner ClientHello (encrypted SNI: sensitive-tenant.com)
CDN Edge → Decrypts Inner → Routes to correct tenant
```

**DNS Bootstrap:** CDN publishes HTTPS/SVCB DNS record with ECH configuration and HPKE encryption key.
**Dual-Payload Construction:** Client builds ClientHello with outer (grease/cover) SNI and inner (encrypted) SNI.
**Edge Termination:** CDN edge decrypts inner payload using private key, discovers real destination.

## 3. Domain Fronting vs ECH

### Domain Fronting
Relies on discrepancy between TLS SNI (benign CDN domain) and HTTP Host header (blocked domain). Both terminate at same CDN. CDNs have systematically deprecated explicit domain fronting because it bypasses tenant authorization boundaries.

### ECH
Solves metadata leakage cleanly within TLS specification. Does not trick the CDN via mismatched headers — cryptographically shields true SNI inside a legitimate TLS extension.

## 4. Mutual TLS (mTLS)

### Viewer mTLS (Client-to-Edge)
- **Cloudflare:** Custom client certificate profiles, feeding certificate metadata into Workers via request headers
- **AWS CloudFront:** Native viewer mTLS with AWS Private CA trust stores. Options: Passthrough Mode or Edge Validation

### Origin mTLS (Edge-to-Origin)
- CDN presents pre-configured client certificate during TLS handshake with origin
- Origin validates CDN's client certificate against trust store
- Ensures only CDN traffic reaches origin even if direct IP is discovered

## 5. Traffic Management APIs

### Routing Strategies
- **Latency-based:** Route to lowest-latency edge
- **Geolocation-based:** Route based on user geography
- **Weighted:** Distribute traffic proportionally across origins
- **Failover:** Automatic backup when primary origin fails

### CDN-as-Proxy Pattern
CDNs can serve as transparent proxies for traffic obfuscation:
- Client traffic appears to go to CDN (legitimate)
- CDN forwards to origin (could be C2 server)
- Network observers see CDN traffic (trusted domain)
- Deep packet inspection reveals only CDN-terminated TLS

## 6. Security Considerations

### Advantages for Legitimate Use
- DDoS protection and traffic scrubbing
- SSL/TLS termination offloading
- Global low-latency content delivery
- Web Application Firewall (WAF) integration

### Security Concerns
- CDN as single point of failure
- CDN operator can see all traffic (privacy concern)
- TLS termination at edge creates trust boundary shift
- Domain fronting abuse for censorship circumvention and C2 communication

## 7. Research Applications for SIH26148

For the JOCKY framework's central management interface, CDN routing enables:
1. **Obfuscated command channel:** Client-to-server traffic routed through trusted CDN
2. **Domain fronting:** Traffic appears to go to legitimate cloud provider
3. **ECH protection:** True destination hidden within encrypted TLS handshake
4. **Resilience:** CDN's anycast architecture provides natural redundancy
5. **Scalability:** Handle thousands of forensic endpoints simultaneously

---

*Word count: ~1200 words | Sources: RFC 9849, Cloudflare, AWS, Microsoft documentation*
