# 0x90JMP Blog

Personal blog covering Windows offensive security research.

Built with [Chirpy](https://github.com/cotes2020/jekyll-theme-chirpy).

## Local Development

```bash
gem install bundler
bundle install
bundle exec jekyll serve
```

Then open `http://localhost:4000`.

## Deployment

Push to `main` — GitHub Actions builds and deploys automatically via `.github/workflows/pages-deploy.yml`.

In your GitHub repo settings: **Pages → Source → GitHub Actions**.

## Category Structure

| Category | Sub-category | Use for |
|---|---|---|
| Malware Development | Loaders | Shellcode loaders, stagers |
| Malware Development | Injectors | Process injection techniques |
| Malware Development | C2 | Implant development, comms |
| AV/EDR Bypass | AMSI | AMSI evasion |
| AV/EDR Bypass | ETW | ETW tampering / patching |
| AV/EDR Bypass | Hooks | Userland hook evasion |
| Active Directory | Enumeration | LDAP, BloodHound |
| Active Directory | Lateral Movement | Pass-the-hash, WMI, etc. |
| Active Directory | Persistence | GPO abuse, etc. |
| Tools & Tradecraft | | Tool releases, OPSEC |

## Post Front Matter Reference

```yaml
---
title: "Post Title"
date: YYYY-MM-DD HH:MM:SS +0000
categories: [Top Category, Sub Category]
tags: [tag1, tag2, tag3]
toc: true
pin: false          # pin to top of home page
# image:
#   path: /assets/img/posts/banner.png
#   alt: "Alt text"
---
```
