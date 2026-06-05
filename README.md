
<div align="center">

```
  __ _  _    _ __ ___  ___ ___  _ __
 / _` || |  | '__/ _ \/ __/ _ \| '_ \
| (_| || |  | | |  __/ (_| (_) | | | |
 \__,_||_|  |_|  \___|\___\___/|_| |_|
```

**AI-powered recon tool for bug bounty & CTF**

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-LLM-F55036?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

</div>

---

Tired of manually reading through recon output and googling what each thing means? This tool gathers DNS, HTTP headers, SSL certs, and tech stack info on a target — then sends it all to an LLM (via Groq) to get an actual analysis with attack vectors and next steps.

Built this for my own CTF/BB workflow. Works well for quick initial recon.

## What it does

- DNS lookup (A, MX, NS, TXT records)
- HTTP/HTTPS info (status, headers, page title, redirects)
- Technology detection from response headers (`Server`, `X-Powered-By`, CMS fingerprinting)
- Missing security headers check
- SSL cert info + SAN domains (bonus subdomains sometimes)
- Sends all of it to `llama-3.3-70b-versatile` via Groq and gets back a structured attack analysis

## Install

```bash
git clone https://github.com/EvgenuXSS/ai-recon
cd ai-recon
pip install -r requirements.txt
```

Get a free Groq API key at [console.groq.com](https://console.groq.com) (it's free, fast)

```bash
export GROQ_API_KEY=your_key_here
```

## Usage

```bash
python3 ai_recon.py example.com
```

Use a different model:
```bash
python3 ai_recon.py example.com --model mixtral-8x7b-32768
```

## Example output

```
[*] target: example.com
[*] model: llama-3.3-70b-versatile
[*] started at 14:23:01

[*] DNS recon...
    IP: 93.184.216.34
[*] HTTP recon...
    HTTPS 200 — Example Domain
    missing headers: Content-Security-Policy, X-Frame-Options
[*] SSL/TLS info...
    SANs: example.com, www.example.com

[*] asking llama-3.3-70b-versatile for analysis...

============================================================
## Technology Stack
Based on the headers, this appears to be a standard nginx server...

## Potential Attack Vectors
1. Missing CSP — XSS would not be blocked by policy...
...
============================================================
```

## Supported models

Any model available on Groq works. Fast ones:
- `llama-3.3-70b-versatile` (default, best results)
- `llama-3.1-8b-instant` (faster, less detailed)
- `mixtral-8x7b-32768` (good for long output)

## Notes

- Only test targets you have permission to test
- Groq free tier is more than enough for this
- `dig` needs to be installed for full DNS records (optional, falls back to socket)

---

*made by [EvgenuXSS](https://github.com/EvgenuXSS)*
