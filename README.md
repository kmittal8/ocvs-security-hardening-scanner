# VMware vSphere Security Hardening Scanner

> Automated SOC compliance scanning, AI-powered RAG pipeline via OCI Generative AI, and auto-remediation for VMware vSphere environments — deployed on Oracle Cloud Infrastructure.

![VMware vSphere 8](https://img.shields.io/badge/VMware%20vSphere-8-blue?style=flat-square&logo=vmware)
![Oracle Cloud](https://img.shields.io/badge/Oracle%20Cloud-OCI-red?style=flat-square&logo=oracle)
![Terraform](https://img.shields.io/badge/Terraform-IaC-purple?style=flat-square&logo=terraform)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-ff4b4b?style=flat-square&logo=streamlit)

---

## What This Project Does

This platform automates the tedious manual work of hardening VMware vSphere 8 environments. It connects directly to vCenter, runs **60+ compliance checks** against the *VMware vSphere Security Configuration Guide v8 (SCG v8)*, remediates failed controls automatically, and generates AI-powered PDF reports — all from a browser-based dashboard deployed on OCI.

### The Pipeline

```
① SCAN PIPELINE
vCenter / ESXi  →  pyVmomi SDK  →  Compliance Engine (60+ checks)  →  Scan Results  →  Auto-Remediate

② RAG PIPELINE
Scan Results  →  Result Cache (JSON)  →  OCI GenAI (LLM)  →  AI Narrative  →  PDF Report
```

---

## Key Capabilities

| Capability | Description |
|---|---|
| **Automated Auditing** | Scans ESXi hosts, vCenter, VMs, and virtual networking against SCG v8 — all domains or selectively |
| **Auto-Remediation** | Applies fixes for failed controls directly via the pyVmomi API where safe automation is supported |
| **RAG Pipeline** | Persists scan results as structured context, feeds them into OCI GenAI to produce grounded plain-language narratives |
| **PDF Reporting** | Generates SOC-ready PDF reports with charts, PASS/FAIL tables, and AI-written remediation guidance |
| **Result Caching** | Persists scan data to disk for trend comparison across audit runs without reconnecting to vCenter |
| **IaC Deployment** | One `terraform apply` spins up the entire OCI VM + networking stack; `terraform destroy` tears it down |

---

## OCI Services Used

| OCI Service | Role |
|---|---|
| **OCI Compute — VM.Standard3.Flex** | Scanner VM (Oracle Linux 9, 2 OCPUs / 16 GB) — right-sized, ephemeral |
| **OCI VCN + Security Lists** | Network isolation — SSH (22) and Streamlit dashboard (8501) |
| **OCI Generative AI** | LLM endpoint (`ap-hyderabad-1`) powering the RAG pipeline |
| **OCI Terraform Provider v5** | Full infrastructure-as-code lifecycle for all OCI resources |

> **Data Residency:** All AI calls stay within the OCI tenancy. No compliance data is sent to external AI providers.

---

## Compliance Domains (SCG v8)

- **Identity & Access Management** — Account lockout, session timeouts, lockdown mode, SSO hardening, login banners
- **Network Security** — BPDU blocking, DVFilter restrictions, PVLAN/VGT prevention, vSwitch port-group policy
- **Services & Features** — SSH/Shell disable, MOB disable, Secure Boot, firewall rules, NTP validation
- **VM Hardening** — USB/serial/parallel port restrictions, console limits, guest OS isolation
- **Logging & Audit** — Syslog config, audit capacity, remote TLS, persistent logging, TPS audit
- **System Hardening** — TLS protocol restrictions, SSH cipher audit, VIB acceptance, FIPS for SSH, vSAN checks

---

## Technology Stack

| Layer | Technology |
|---|---|
| Application | Python 3.10+ / Streamlit |
| vSphere API | pyVmomi (VMware SDK) |
| AI / GenAI | OCI Generative AI |
| PDF Generation | ReportLab |
| Data Processing | Pandas |
| Infrastructure | Terraform (OCI Provider v5) |
| OS | Oracle Linux 9 |

---

## Project Structure

```
VMware_Security_Hardening/
│
├── index.html                          ← Project overview page
│
└── terraform/
    └── ocvs_scanner_vm/
        ├── app.py                      ★ Main app — 2,700+ lines
        │                                 Streamlit UI + 60+ compliance checks
        │                                 OCI GenAI RAG pipeline + PDF reporting
        │
        ├── main.tf                     ★ OCI infrastructure (compute, VCN, SSH keys)
        ├── variables.tf                  Variable declarations
        ├── terraform.tfvars.example      Safe config template — copy to terraform.tfvars
        └── .terraform.lock.hcl           Provider version locks
```

---

## Deployment

```bash
# 1. Copy config template and fill in your OCI credentials
cp terraform/ocvs_scanner_vm/terraform.tfvars.example terraform/ocvs_scanner_vm/terraform.tfvars

# 2. Initialise Terraform providers
cd terraform/ocvs_scanner_vm && terraform init

# 3. Preview resources
terraform plan

# 4. Deploy OCI VM + networking
terraform apply

# 5. SSH into the instance
ssh -i id_rsa_ocvs_scanner opc@<public-ip>

# 6. Start the Streamlit dashboard (on the VM)
streamlit run app.py --server.port 8501

# 7. Open in browser
http://<public-ip>:8501

# 8. Teardown when done
terraform destroy
```

---

## References

- [VMware vSphere Security Configuration Guide v8](https://www.vmware.com/security/hardening-guides.html)
- [Oracle Cloud Infrastructure](https://www.oracle.com/cloud/)
- [OCI Generative AI](https://www.oracle.com/artificial-intelligence/generative-ai/)
- [Terraform OCI Provider](https://registry.terraform.io/providers/oracle/oci/latest/docs)

---

*Built with Oracle Cloud Infrastructure & Anthropic Claude*
