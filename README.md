# DNS Resolution & HTTPS/TLS Handshake — Packet-Level Analysis

## Objective
Trace a DNS lookup and a full HTTPS/TLS handshake using command-line tools, then verify and inspect that traffic at the packet level with Wireshark — including locating the cleartext Server Name Indication (SNI) field inside an otherwise encrypted TLS session.

## Environment
- **Machine:** Kali Linux (VirtualBox, NAT networking for internet access)
- **Tools used:** `dig`, `curl`, Wireshark
- **Target domain:** example.com

## 1. DNS Resolution — Command Line

Ran a standard DNS lookup against example.com:

```
dig example.com
```

**Result:**
```
;; ANSWER SECTION:
example.com.    9   IN   A   172.66.147.243
example.com.    9   IN   A   104.20.23.154
;; SERVER: 192.168.1.1#53(192.168.1.1) (UDP)
;; MSG SIZE  rcvd: 72
```

Two A records were returned (common for load-balanced/CDN-fronted domains), with a 9-second TTL, resolved over UDP via the local resolver (192.168.1.1).

## 2. HTTPS Request and TLS Handshake — Command Line

```
curl -v https://example.com
```

**Key output:**
```
* Host example.com:443 was resolved.
* IPv4: 172.66.147.243, 104.20.23.154
* ALPN: curl offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* ALPN: server accepted h2
* Server certificate:
*  subject: CN=example.com
*  start date: Sep 26 22:49:11 2026 GMT
*  expire date: Dec 25 22:56:35 2026 GMT
*  issuer: C=US; O=SSL Corporation; CN=Cloudflare TLS Issuing ECC CA 3
```

curl's verbose output confirms the full TLS 1.3 handshake sequence end to end, the negotiated cipher suite, and the server's certificate details — all without needing a packet capture. The question is whether this same information is visible at the network layer, and what remains exposed even though the session is "encrypted."

## 3. Packet-Level Verification (Wireshark)

A capture was taken on Kali's interface spanning both the `dig` lookup and the `curl` request.

**DNS traffic (filter: `dns`):**
The capture showed the outbound query (10.0.2.15 → 192.168.1.1) and the matching response, with the Answers section listing the same two A records (172.66.147.243, 104.20.23.154) returned by `dig` — confirming the resolver's answer was captured accurately at the packet level.

**TLS handshake traffic (filter: `tls.handshake`):**
The same handshake sequence seen in curl's `-v` output was visible as individual packets: Client Hello, Server Hello, Certificate, and Finished messages, each as a distinct TCP segment.

**Server Name Indication (SNI):**
Inside the Client Hello packet, under `Transport Layer Security > Handshake Protocol: Client Hello > Extension: server_name > Server Name Indication extension`, the field **Server Name** contained `example.com` in **plain text**.

## Key Findings

1. **DNS resolution is fully visible on the wire by design.** Standard DNS (UDP/53) carries both the query and the answer in cleartext — anyone capturing traffic on the path can see exactly which domains a host is resolving.
2. **TLS protects the content, not the destination.** Despite negotiating TLS 1.3 with a strong cipher suite (TLS_AES_256_GCM_SHA384), the very first packet of the handshake — the Client Hello — exposes the target hostname in cleartext via the SNI extension. This is a structural property of TLS (prior to encrypted ClientHello / ECH adoption), not a misconfiguration.
3. **This is exactly what SOC tooling relies on.** Since HTTP payload content is encrypted, detection and monitoring tools lean heavily on metadata that remains visible: the SNI hostname, certificate subject/issuer, and JA3-style handshake fingerprints — enabling network-level visibility into *what* a host is connecting to, even without decrypting *what* it's sending.

## Relevance to Detection
- Firewalls and proxies commonly use SNI inspection to allow/block HTTPS traffic by domain without needing to terminate TLS.
- A mismatch between the SNI hostname and the certificate's subject/SAN fields is a known phishing/MITM indicator.
- DNS query logging (query name, source host, timestamp) is a standard and effective detection data source for identifying C2 beaconing or data exfiltration, since the query itself is never encrypted in classic DNS.

---
*Performed in a lab environment as part of a 30-day SOC L1/L2 analyst preparation plan.*
