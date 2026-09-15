# 🧭 TenantConfigReport

**A single PowerShell script that gives you a first-look, executive-ready picture of any Microsoft 365 / Entra ID tenant — dashboard-first, drill-down detail below.**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white)](#-requirements)
[![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-SDK-0078D4?logo=microsoft&logoColor=white)](https://learn.microsoft.com/graph/powershell/get-started)
[![License](https://img.shields.io/github/license/ChrisMunnPS/TenantConfigReport)](LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/ChrisMunnPS/TenantConfigReport)](https://github.com/ChrisMunnPS/TenantConfigReport/commits/main)
[![Issues](https://img.shields.io/github/issues/ChrisMunnPS/TenantConfigReport)](https://github.com/ChrisMunnPS/TenantConfigReport/issues)
[![Stars](https://img.shields.io/github/stars/ChrisMunnPS/TenantConfigReport?style=social)](https://github.com/ChrisMunnPS/TenantConfigReport/stargazers)

---

## 📋 Executive Summary

`Get-TenantConfigReport.ps1` connects to a Microsoft 365 tenant as a **Global Admin / Global Reader** and produces one report covering identity, security, mail, and file-sharing configuration in a single run. It's built for the moment you're looking at a tenant for the first time — a new client, a new job, an audit — and need the full picture without stitching together a dozen admin-center screens.

It pulls from three services — **Microsoft Graph (Entra ID)**, **Exchange Online**, and **SharePoint Online** — and outputs **three formats** from one data collection pass: an interactive **HTML dashboard**, a **Markdown** file (with full per-user detail, easy to diff or paste into a wiki), and a **PDF** (client-ready, one click to share).

| | |
|---|---|
| ⏱️ **Time to run** | A few minutes on most tenants; SharePoint site enumeration scales with site count |
| 🔑 **Access needed** | Global Reader (read-only, recommended) or Global Admin |
| 📦 **Dependencies** | Auto-installed on first run — no manual setup |
| 🧩 **Resilience** | Each section is independent; a missing module or failed connection skips that section, not the whole run |
| 📤 **Output** | `TenantReport.html` · `TenantReport.md` · `TenantReport.pdf` in a timestamped folder |

---

## 📑 Table of Contents

- [✨ Features](#-features)
- [🖼️ Sample Output](#️-sample-output)
- [📦 Requirements](#-requirements)
- [🚀 Installation](#-installation)
- [▶️ Usage](#️-usage)
- [⚙️ Parameters](#️-parameters)
- [🔍 What Gets Collected](#-what-gets-collected)
- [🔐 Permissions & Scopes](#-permissions--scopes)
- [🗂️ Output Structure](#️-output-structure)
- [❓ Troubleshooting](#-troubleshooting)
- [🗺️ Roadmap](#️-roadmap)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## ✨ Features

- 📊 **Dashboard-first HTML report** — summary cards at the top, sticky nav, color-coded health pills, full detail tables below
- 🧱 **Three services, one run** — Entra ID, Exchange Online, SharePoint Online / OneDrive
- 🛡️ **Security-aware** — Conditional Access, MFA/auth method registration, admin role sprawl, risky app permissions all called out
- 🩹 **Fails gracefully** — missing module or blocked connection skips that section and logs a warning instead of aborting
- 🏢 **MSP-friendly** — `-TenantId` switches target tenant without reinstalling anything
- 📤 **Three output formats** from a single data pull — HTML, Markdown, PDF (via headless Edge, no extra dependency)
- 🧾 **Full audit trail** — every collection failure is recorded and shown in the report itself, not just the console

---

## 🖼️ Sample Output

Below is what the report looks like for a **fictitious** tenant, `contoso.com` — sample data only.

### Dashboard cards (top of `TenantReport.html`)

| 🏢 Tenant | 👥 Users | ⚠️ Stale Accounts (90d+) | 👨‍👩‍👧 Groups |
|---|---|---|---|
| **Contoso Ltd**<br>contoso.com | **150**<br>140 enabled · 5 guests | **12**<br>no recent sign-in | **40**<br>4 ownerless |

| 📜 License SKUs | 🛡️ Global Admins | 🚦 Conditional Access | 🔑 MFA Capable |
|---|---|---|---|
| **1**<br>avg 87% consumed | **3**<br>✅ healthy range | **8**<br>6 enabled · 1 report-only | **80%**<br>⚠️ 1 admin without MFA |

| 📧 Mailboxes | 📁 SharePoint Storage |
|---|---|
| **140**<br>4 mail flow rules | **245.6 GB**<br>60 sites |

### Detail section excerpt — Licenses

| SKU | Consumed | Enabled | Available | % Used |
|---|---|---|---|---|
| ENTERPRISEPACK | 130 | 150 | 20 | 🟠 **86.7%** |

### Detail section excerpt — Admin Roles

| Role | Members | Who |
|---|---|---|
| Global Administrator | 3 | Jane Doe, John Smith, Admin User |
| Exchange Administrator | 2 | John Smith, Helpdesk Lead |

### Detail section excerpt — Conditional Access

| Policy | State | Users | Apps | Grant Controls |
|---|---|---|---|---|
| Require MFA for all users | 🟢 enabled | All users | All apps | mfa |
| Block legacy authentication | 🟢 enabled | All users | All apps | block |
| Pilot: require compliant device | 🟡 enabledForReportingButNotEnforced | Scoped | Scoped | compliantDevice |

### Detail section excerpt — MFA & Authentication Methods

| Metric | Value |
|---|---|
| Users Reported | 150 |
| MFA Capable | 120 (80.0%) |
| Security Defaults Enabled | False |
| Admins without MFA | 1 — `admin2@contoso.com` |

### Collection Warnings (shown when a section can't be reached)

> ⚠️ `[ExchangeOnline] Connection failed: Access denied — account lacks an Exchange admin role`

The rest of the report renders normally; only that one section shows as skipped.

---

## 📦 Requirements

- **PowerShell 5.1+** (Windows PowerShell or PowerShell 7)
- **Windows** (PDF export shells out to `msedge.exe` in headless mode)
- **Microsoft Edge** installed, for PDF export (HTML/Markdown work without it)
- An account with **Global Reader** or **Global Admin** in the target tenant
- Internet access to install PowerShell modules on first run:
  - `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Groups`, `Microsoft.Graph.Identity.DirectoryManagement`, `Microsoft.Graph.Identity.SignIns`, `Microsoft.Graph.Applications`, `Microsoft.Graph.Reports`
  - `ExchangeOnlineManagement` (unless `-SkipExchange`)
  - `PnP.PowerShell` (unless `-SkipSharePoint`)

---

## 🚀 Installation

```powershell
git clone https://github.com/ChrisMunnPS/TenantConfigReport.git
cd TenantConfigReport
```

No further setup needed — required modules are checked and installed to `CurrentUser` scope automatically the first time you run the script.

---

## ▶️ Usage

```powershell
# Full report, current directory, interactive sign-in
.\Get-TenantConfigReport.ps1

# Target a specific tenant (MSP scenario) and choose an output folder
.\Get-TenantConfigReport.ps1 -TenantId 'contoso.onmicrosoft.com' -OutputPath 'C:\Reports'

# Entra ID / Graph only — fastest option, no Exchange or SharePoint modules required
.\Get-TenantConfigReport.ps1 -SkipExchange -SkipSharePoint

# Skip PDF generation (HTML + Markdown only)
.\Get-TenantConfigReport.ps1 -SkipPdf
```

You'll be prompted to sign in once per connected service (up to three times: Graph, Exchange Online, SharePoint Online).

---

## ⚙️ Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-OutputPath` | string | current directory | Folder the timestamped report folder is created in |
| `-TenantId` | string | *(caller's default tenant)* | Tenant ID or verified domain — for MSPs targeting a specific customer tenant |
| `-SkipExchange` | switch | off | Skip the Exchange Online connection and section |
| `-SkipSharePoint` | switch | off | Skip the SharePoint Online connection and section |
| `-SkipPdf` | switch | off | Skip PDF generation (HTML and Markdown are unaffected) |

---

## 🔍 What Gets Collected

| Section | Highlights |
|---|---|
| 🏢 Tenant & Domains | Display name, tenant ID, default domain, verified domains, hybrid sync status |
| 👥 Users | Total/enabled/disabled, guest vs member, cloud-only vs hybrid, licensed vs not, stale (90d+) accounts, full per-user table |
| 👨‍👩‍👧 Groups | Counts by type (M365 / Security / Mail-Enabled Security / Distribution / Dynamic), ownerless groups flagged |
| 📜 Licenses | SKU consumption vs available, near-exhaustion (≥90%) flagged |
| 🛡️ Admin Roles | Every privileged role and its members; Global Admin count flagged outside the recommended 2–4 range |
| 🚦 Conditional Access | Every policy, state, target users/apps, grant controls |
| 🔑 MFA & Authentication | Registration coverage %, Security Defaults status, admins without MFA named individually |
| 🧩 Applications | App registrations ranked by requested permission count — highest-risk apps surface first |
| 📧 Exchange Online | Mailbox counts by type, mail flow (transport) rules, inbound/outbound connectors |
| 📁 SharePoint & OneDrive | Site count, total storage, tenant/OneDrive sharing capability, default link permission, legacy auth status |

---

## 🔐 Permissions & Scopes

**Microsoft Graph scopes requested:**
`Organization.Read.All` · `User.Read.All` · `Group.Read.All` · `RoleManagement.Read.Directory` · `Policy.Read.All` · `Reports.Read.All` · `Application.Read.All` · `AuditLog.Read.All` · `Directory.Read.All`

All scopes are **read-only**. Exchange Online and SharePoint Online connections use the same signed-in admin account and only call read cmdlets.

---

## 🗂️ Output Structure

```
TenantReport_contoso_20260915-143000/
├── TenantReport.html   ← dashboard + full detail, open in any browser
├── TenantReport.md     ← same content + full per-user table, good for wikis/diffs
└── TenantReport.pdf    ← client-ready export (skipped if Edge isn't found)
```

---

## ❓ Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| A section shows "unavailable — see warnings" | Missing module, failed connection, or insufficient permissions | Check the **Collection Warnings** box at the bottom of the report for the exact error |
| No PDF produced | `msedge.exe` not found on this machine | Install Microsoft Edge, or use `-SkipPdf` and open the HTML/Markdown instead |
| SharePoint section is slow | Large number of site collections | Expected — `Get-PnPTenantSite` scales with site count; let it finish |
| Prompted to sign in multiple times | Normal | Graph, Exchange Online, and SharePoint Online each authenticate separately |

---


## 🤝 Contributing

Issues and pull requests are welcome — please open an issue first for anything beyond a small fix so the approach can be agreed on before you put the work in.

---

## 📄 License

Released under the [MIT License](LICENSE).
