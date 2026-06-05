#!/usr/bin/env python3
"""
ai-recon — gathers recon data on a target and asks an LLM to analyze it
requires: GROQ_API_KEY env variable
"""

import socket
import ssl
import sys
import os
import json
import requests
import urllib3
from datetime import datetime

urllib3.disable_warnings()

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "llama-3.3-70b-versatile"

BANNER = r"""
  __ _  _    _ __ ___  ___ ___  _ __
 / _` || |  | '__/ _ \/ __/ _ \| '_ \
| (_| || |  | | |  __/ (_| (_) | | | |
 \__,_||_|  |_|  \___|\___\___/|_| |_|
                         by EvgenuXSS
"""


def get_dns_info(domain):
    results = {}
    try:
        results["ipv4"] = socket.gethostbyname(domain)
    except:
        results["ipv4"] = None

    try:
        import subprocess
        for record_type in ["A", "MX", "NS", "TXT"]:
            out = subprocess.run(
                ["dig", "+short", record_type, domain],
                capture_output=True, text=True, timeout=5
            )
            if out.stdout.strip():
                results[record_type] = out.stdout.strip().split("\n")
    except:
        pass

    return results


def get_http_info(target):
    results = {}
    for scheme in ["https", "http"]:
        url = f"{scheme}://{target}"
        try:
            r = requests.get(url, timeout=7, verify=False,
                             allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0"})

            results["status_code"] = r.status_code
            results["final_url"] = r.url
            results["headers"] = dict(r.headers)
            results["scheme"] = scheme

            # технологии из заголовков
            tech = []
            h = r.headers
            if "X-Powered-By" in h:
                tech.append(f"X-Powered-By: {h['X-Powered-By']}")
            if "Server" in h:
                tech.append(f"Server: {h['Server']}")
            if "X-Generator" in h:
                tech.append(f"Generator: {h['X-Generator']}")
            if "X-AspNet-Version" in h:
                tech.append(f"ASP.NET: {h['X-AspNet-Version']}")
            if "X-Drupal-Cache" in h:
                tech.append("CMS: Drupal")
            if "wp-content" in r.text[:5000]:
                tech.append("CMS: WordPress")
            if "Joomla" in r.text[:5000]:
                tech.append("CMS: Joomla")

            results["detected_tech"] = tech

            # пропущенные security headers
            missing = []
            for sh in ["Content-Security-Policy", "X-Frame-Options",
                       "X-Content-Type-Options", "Strict-Transport-Security"]:
                if sh not in h:
                    missing.append(sh)
            results["missing_security_headers"] = missing

            # вытащить title
            import re
            title_match = re.search(r"<title>(.*?)</title>", r.text[:3000], re.IGNORECASE)
            results["page_title"] = title_match.group(1) if title_match else ""

            break
        except Exception as e:
            results[f"{scheme}_error"] = str(e)

    return results


def get_ssl_info(domain):
    results = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            results["subject"] = dict(x[0] for x in cert.get("subject", []))
            results["issuer"] = dict(x[0] for x in cert.get("issuer", []))
            results["valid_until"] = cert.get("notAfter", "")
            san = cert.get("subjectAltNames", [])
            results["san_domains"] = [x[1] for x in san if x[0] == "DNS"]
    except Exception as e:
        results["error"] = str(e)
    return results


def ask_groq(recon_data, target, api_key, model=DEFAULT_MODEL):
    summary = json.dumps(recon_data, indent=2, ensure_ascii=False)

    prompt = f"""You are an experienced bug bounty hunter and penetration tester.
I just ran reconnaissance on: {target}

Here is the collected data:
{summary}

Analyze this data and provide:
1. **Technology Stack** — what's running on this target
2. **Potential Attack Vectors** — specific vulnerabilities worth testing based on what you see
3. **Missing Security Headers** — and what attacks they enable
4. **Interesting Findings** — anything unusual or suspicious
5. **Recommended Next Steps** — what to test first, in priority order

Be specific and actionable. Skip generic advice. Focus on what's actually interesting in this data."""

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.4,
        "max_tokens": 1500
    }

    try:
        r = requests.post(GROQ_API_URL, headers=headers,
                          json=payload, timeout=30)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    except requests.exceptions.HTTPError as e:
        return f"[!] Groq API error: {e}\n{r.text}"
    except Exception as e:
        return f"[!] error calling Groq: {e}"


def main():
    print(BANNER)

    if len(sys.argv) < 2:
        print(f"usage: python3 {sys.argv[0]} <domain/ip> [--model MODEL]")
        print(f"example: python3 {sys.argv[0]} example.com")
        print(f"\nset GROQ_API_KEY env variable before running")
        sys.exit(0)

    target = sys.argv[1].strip().removeprefix("http://").removeprefix("https://").split("/")[0]

    model = DEFAULT_MODEL
    if "--model" in sys.argv:
        idx = sys.argv.index("--model")
        if idx + 1 < len(sys.argv):
            model = sys.argv[idx + 1]

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("[!] GROQ_API_KEY not set")
        print("    export GROQ_API_KEY=your_key_here")
        sys.exit(1)

    print(f"[*] target: {target}")
    print(f"[*] model: {model}")
    print(f"[*] started at {datetime.now().strftime('%H:%M:%S')}\n")

    recon = {}

    print("[*] DNS recon...")
    recon["dns"] = get_dns_info(target)
    if recon["dns"].get("ipv4"):
        print(f"    IP: {recon['dns']['ipv4']}")

    print("[*] HTTP recon...")
    recon["http"] = get_http_info(target)
    if "status_code" in recon["http"]:
        print(f"    {recon['http']['scheme'].upper()} {recon['http']['status_code']} — {recon['http'].get('page_title','')}")
    if recon["http"].get("detected_tech"):
        print(f"    tech: {', '.join(recon['http']['detected_tech'])}")
    if recon["http"].get("missing_security_headers"):
        print(f"    missing headers: {', '.join(recon['http']['missing_security_headers'])}")

    print("[*] SSL/TLS info...")
    recon["ssl"] = get_ssl_info(target)
    if recon["ssl"].get("san_domains"):
        print(f"    SANs: {', '.join(recon['ssl']['san_domains'][:5])}")

    print(f"\n[*] asking {model} for analysis...\n")
    print("=" * 60)

    analysis = ask_groq(recon, target, api_key, model)
    print(analysis)

    print("=" * 60)
    print(f"\n[*] done at {datetime.now().strftime('%H:%M:%S')}")


if __name__ == "__main__":
    main()
