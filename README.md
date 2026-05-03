# Email-Hunter

A fast, modular command-line email reconnaissance tool built with Node.js. Validates email addresses, performs DNS/MX lookups, attempts SMTP verification, detects disposable providers, and optionally checks against the **HaveIBeenPwned** breach database.

## Features

- **Format Validation:** Strict regex-based email format check before any network requests.
- **Disposable Detection:** Checks the domain against a curated list of 40+ known throwaway email providers.
- **DNS / MX Lookup:** Resolves MX and A records for the target domain using Node's native `dns/promises` module.
- **SMTP Verification:** Connects directly to the primary MX server on port 25 and performs a full EHLO → MAIL FROM → RCPT TO handshake to verify if the mailbox exists.
- **HaveIBeenPwned Integration:** Checks the email against all known public data breaches via the HIBP v3 API (requires a free API key).
- **Clean CLI UI:** Color-coded terminal output using `chalk` — green for safe, yellow for warnings, red for issues.

## Prerequisites

- [Node.js](https://nodejs.org/) (v18.0.0 or higher recommended)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/email-hunter.git
   cd email-hunter
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

## Usage

```bash
node email-hunter.js <email> [--hibp-key <key>]
```

### Basic scan (no API key required)

```bash
node email-hunter.js target@example.com
```

Runs format validation, disposable check, DNS/MX lookup, and SMTP verification.

### Full scan with HaveIBeenPwned

```bash
node email-hunter.js target@example.com --hibp-key YOUR_API_KEY_HERE
```

Adds breach database lookup on top of all basic checks.

> 💡 Get a free HIBP API key at [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key)

## What Each Check Does

| Check | Method | Requires API key? |
|---|---|---|
| Format Validation | Regex | No |
| Disposable Detection | Local domain list | No |
| MX / A Record Lookup | Node `dns/promises` | No |
| SMTP Verification | Raw TCP socket on port 25 | No |
| Breach Detection | HIBP v3 API | Yes (free) |

## Example Output

```
  [*] Target » target@gmail.com
  ────────────────────────────────────────────────────────────

  [~] Validating email format...
  [✓] Format is valid
  [i] Domain: gmail.com

  [~] Checking disposable email providers...
  [✓] Not a known disposable provider

  ────────────────────────────────────────────────────────────

  [~] Performing DNS lookups...
  [✓] MX Records (5 found):
       5    → gmail-smtp-in.l.google.com
       10   → alt1.gmail-smtp-in.l.google.com
       ...
  [✓] A Records: 142.250.185.46

  ────────────────────────────────────────────────────────────

  [~] Attempting SMTP verification via primary MX...
  [i] Connecting to gmail-smtp-in.l.google.com:25
  [⚠] SMTP: Blocked / Timed out (normal for major providers)

  ────────────────────────────────────────────────────────────

  [i] Tip: Pass --hibp-key <key> to check breach databases.

  ────────────────────────────────────────────────────────────

  [*] Scan complete.
```

> **Note on SMTP:** Large providers like Gmail, Outlook, and Yahoo block port 25 from external IPs as an anti-spam measure. A "blocked" result does **not** mean the email is invalid — it means the server refuses to answer SMTP probes. SMTP verification works best against smaller/corporate mail servers.

## Tech Stack

- **Node.js:** Core runtime environment.
- **dns/promises:** Native module for MX and A record resolution.
- **net:** Native module for raw TCP socket connections (SMTP).
- **axios:** Promise-based HTTP client for HIBP API requests.
- **chalk:** Terminal string styling.

## Disclaimer

This tool is built for **educational purposes** and **ethical security research** only. Do not use it to spam, scrape, or harass individuals. Always obtain proper authorization before scanning email addresses that do not belong to you.
