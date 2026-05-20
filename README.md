# EmberHoneypot

**AI deception and live threat intelligence platform.** Deploys decoy AI infrastructure to lure, capture, and profile attackers — then enriches every captured technique with real-time CVE and campaign data via Perplexity Sonar.

[![Tests](https://img.shields.io/badge/tests-184%20passing-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## What It Does

Traditional honeypots log IP addresses. EmberHoneypot captures **attacker techniques** — mapped to MITRE ATT&CK IDs — and immediately enriches them with live threat intelligence:

```
Attacker interaction
        ↓
   TTP Extractor         (MITRE ATT&CK technique mapping)
        ↓
 SonarIntelligenceClient (Perplexity Sonar — live CVE + campaign lookup)
        ↓
  Threat Scorer          (risk assessment with real-world context)
        ↓
  Intelligence Report    (CVEs, threat actors, patch status, citations)
```

**Static pattern matching tells you what happened. Sonar tells you who is doing it now and how fresh the attack is.**

---

## Sonar Integration *(load-bearing)*

`intel/sonar_enrichment.py` — `SonarIntelligenceClient`

After TTP extraction, Sonar queries the live web for:
- **CVE enrichment:** Disclosures in the last 30 days actively exploited via the captured techniques, with severity and patch status
- **Campaign attribution:** Known threat actor groups using those TTPs in the last 7 days
- **Domain context:** Financial sector deployments get different enrichment context than healthcare or legal

Every enrichment result includes Sonar's source citations. Without Sonar, threat intelligence is frozen at training-data cutoff. With Sonar, every captured attacker interaction is cross-referenced against the current threat landscape.

When Sonar is unavailable, the result returns `SONAR_UNAVAILABLE` status — the system degrades gracefully but the audit log is explicit. It never silently skips enrichment.

---

## Architecture

```
EmberHoneypot/
├── core/          — Engine, orchestrator, emulator, attacker profiler, rate limiter
├── deception/     — Decoy personas, disinformation injector, fake data generator, response engine
├── intel/
│   ├── sonar_enrichment.py   — SonarIntelligenceClient (Perplexity Sonar, load-bearing)
│   ├── ttp_extractor.py      — MITRE ATT&CK technique mapping
│   ├── threat_scorer.py      — Risk assessment with live-world context
│   ├── ioc_generator.py      — Indicator of compromise generation
│   └── pattern_matcher.py    — Known attacker signature detection
├── swarm/         — Adaptive defense, threat feed publisher, Centuria adapter
├── monitoring/    — Health checks, Prometheus metrics, structured logging, tracing
└── api/           — FastAPI server with WebSocket support
```

---

## Quick Start

```bash
pip install -e ".[dev]"

# Required
export HONEYPOT_API_KEY="your-secure-key-minimum-32-chars"

# Optional — enables live Sonar threat enrichment
export PERPLEXITY_API_KEY="pplx-..."

uvicorn honeypot.api.main:app --host 0.0.0.0 --port 8001
```

Copy `.env.example` to `.env`. Never commit `.env`.

---

## Tests

```bash
pytest tests/ -v
# 184 tests, 0 failing
```

Includes `tests/test_sonar_enrichment.py` — 30 tests covering fail-closed behavior, CVE extraction, campaign detection, severity inference, novelty assessment, confidence boosting, and telemetry.

---

## Ecosystem

| Repo | Role |
|------|------|
| [EmberArmor](https://github.com/GrandMastaShake/EmberArmor) | Runtime enforcement layer |
| [EmberHoneypot](https://github.com/GrandMastaShake/EmberHoneypot) | AI deception + threat intel (this repo) |
| [Corporeus](https://github.com/GrandMastaShake/Corporeus) | Static AST vulnerability scanner |
| [EmberBench](https://github.com/GrandMastaShake/EmberBench) | Adversarial evaluation harness |

---

## License

MIT — see [LICENSE](LICENSE)
