<p align="center">
  <img src="https://raw.githubusercontent.com/sorabbyngo-os/.github/main/assets/sorabbyngo-logo.jpg" alt="Sorabbyngo" width="480"/>
</p>

<p align="center">
  <strong>Sentinel OS — Cybersecurity Operations System</strong>
</p>

<p align="center">
  Built on Sorabbyngo AI Kernel · Hardened · Air-gap capable · Forensic-ready
</p>

---

## What this is

Sentinel OS is the cybersecurity surface of the Sorabbyngo AI Kernel. It powers security operations centers, penetration testing environments, threat analysis platforms, and digital forensics workstations.

---

## Key Features

| Feature | Implementation |
|---|---|
| Hardened kernel | CONFIG_HARDENED_USERCOPY, CONFIG_FORTIFY_SOURCE |
| Real-time threat detection | eBPF-based network monitoring |
| Forensic acquisition | Memory dump, disk imaging tools |
| Air-gap operation | Byngonet mesh — no internet required |
| Network isolation | Namespace-based segmentation |
| AI threat analysis | Byngox security agent |

---

## Relationship to Sorabbyngo Kernel

sorabbyngo-os (kernel source)
└── configs/sorabbyngo_sentinel_defconfig
└── sentinel-os (this repo — hardened rootfs + security tooling)

---

## Related Repositories

| Repo | Role |
|---|---|
| [sorabbyngo-os](https://github.com/sorabbyngo-os/sorabbyngo-os) | Kernel source |
| [security](https://github.com/citadel-sec/security) | 7-ring defense architecture |
| [dmz](https://github.com/sorabbyngo-os/dmz) | One-way wall — PRIME isolation |
| [byngonet](https://github.com/sorabbyngo-os/byngonet) | Secure mesh protocol |
| [cml](https://github.com/sorabbyngo-os/cml) | Safety and audit layer |

---

**Sorabbyngo Company** · Kisii, Kenya · 2026
*Rhythm of Digital Life*
