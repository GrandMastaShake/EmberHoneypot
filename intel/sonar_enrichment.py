"""SonarIntelligence — Live threat enrichment via Perplexity Sonar API.

This module is a **load-bearing** integration with the Perplexity Sonar API.
It performs real-time web intelligence enrichment for attacker TTPs captured
by the EmberHoneypot system.

Why Sonar is load-bearing here
-------------------------------
The TTP extractor maps observed attacker behavior to MITRE ATT&CK technique
IDs. That's static pattern matching — it tells you *what* happened. Sonar
closes the loop by querying the live web for:

  * Current CVE disclosures associated with those technique IDs
  * Known threat actor campaigns using those TTPs right now
  * Recent exploit news and proof-of-concept releases
  * Patch/mitigation status for newly disclosed vulnerabilities

Without Sonar, threat intelligence is frozen at training-data cutoff. With
Sonar, every captured attacker interaction is cross-referenced against the
current threat landscape. The system fails informatively (not silently) when
Sonar is unavailable — audit logs include SONAR_UNAVAILABLE so operators
know the enrichment layer was offline.

Integration point
-----------------
Called from ``intel/ttp_extractor.py`` after TTPs are extracted, and from
``intel/threat_scorer.py`` during risk assessment. Can also be invoked
directly from the EmberHoneypot API to enrich a specific session on demand.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SONAR_BASE_URL: str = "https://api.perplexity.ai"
SONAR_ENDPOINT: str = "/v1/sonar"
SONAR_MODEL: str = "sonar-pro"          # Real-time web search, grounded responses
SONAR_TIMEOUT_SECONDS: float = 15.0     # Threat intel queries can take a moment
MAX_RETRIES: int = 2
RETRY_BACKOFF_SECONDS: float = 1.5

# Sonar search scopes for different enrichment modes
CVE_SEARCH_RECENCY = "month"            # CVEs from last 30 days
CAMPAIGN_SEARCH_RECENCY = "week"        # Active campaigns: rolling 7-day window


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class SonarStatus(str, Enum):
    """Status of a Sonar enrichment call."""
    SUCCESS = "SUCCESS"
    UNAVAILABLE = "SONAR_UNAVAILABLE"
    TIMEOUT = "SONAR_TIMEOUT"
    RATE_LIMITED = "SONAR_RATE_LIMITED"
    INVALID_KEY = "SONAR_INVALID_KEY"
    ERROR = "SONAR_ERROR"


@dataclass
class CVERecord:
    """A CVE record returned by Sonar enrichment."""
    cve_id: str
    description: str
    severity: str                       # CRITICAL / HIGH / MEDIUM / LOW
    published_date: str
    affected_products: list[str] = field(default_factory=list)
    patch_available: bool = False
    source_url: str = ""


@dataclass
class CampaignRecord:
    """A known threat actor campaign record."""
    campaign_name: str
    threat_actor: str
    ttps_used: list[str] = field(default_factory=list)
    targeted_sectors: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_active: str = ""
    confidence: float = 0.5
    source_url: str = ""


@dataclass
class SonarEnrichmentResult:
    """Complete enrichment result for a set of TTPs."""
    status: SonarStatus
    ttp_ids: list[str]
    cves: list[CVERecord] = field(default_factory=list)
    campaigns: list[CampaignRecord] = field(default_factory=list)
    raw_summary: str = ""
    citations: list[str] = field(default_factory=list)
    enrichment_time_ms: float = 0.0
    model_used: str = SONAR_MODEL
    error_detail: str = ""


# ---------------------------------------------------------------------------
# Sonar client
# ---------------------------------------------------------------------------

class SonarIntelligenceClient:
    """Live threat enrichment client backed by Perplexity Sonar API.

    Parameters
    ----------
    api_key:
        Perplexity API key. Falls back to the ``PERPLEXITY_API_KEY`` env var.
    model:
        Sonar model to use. Default: ``sonar-pro`` (real-time web grounding).
    timeout:
        Per-request HTTP timeout in seconds.

    Thread/async safety
    -------------------
    Uses a shared ``httpx.AsyncClient`` for connection pooling. Safe for
    concurrent async usage. Call ``close()`` at shutdown or use as an
    async context manager.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = SONAR_MODEL,
        timeout: float = SONAR_TIMEOUT_SECONDS,
    ) -> None:
        self._api_key: str = api_key or os.environ.get("PERPLEXITY_API_KEY", "")
        self._model: str = model
        self._timeout: float = timeout

        if not self._api_key:
            logger.warning(
                "sonar.no_api_key: PERPLEXITY_API_KEY not set — Sonar enrichment will be unavailable"
            )

        self._client: httpx.AsyncClient = httpx.AsyncClient(
            base_url=SONAR_BASE_URL,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            timeout=self._timeout,
        )

        # Telemetry
        self._total_calls: int = 0
        self._successful_calls: int = 0
        self._failed_calls: int = 0
        self._last_call_time: float | None = None

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> "SonarIntelligenceClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def enrich_ttps(
        self,
        ttp_ids: list[str],
        context: str = "",
    ) -> SonarEnrichmentResult:
        """Enrich a list of MITRE ATT&CK TTP IDs with live web intelligence.

        Queries Sonar for:
          1. Recent CVEs associated with these techniques
          2. Known threat actor campaigns using these TTPs

        Parameters
        ----------
        ttp_ids:
            List of MITRE ATT&CK technique IDs (e.g. ``["T1190", "T1059"]``).
        context:
            Optional free-text context (e.g. attacker commands observed) to
            make the Sonar query more targeted.

        Returns
        -------
        SonarEnrichmentResult
            Structured enrichment result. Status is SONAR_UNAVAILABLE if the
            API key is missing or the endpoint is unreachable.
        """
        start = time.perf_counter()
        self._total_calls += 1
        self._last_call_time = time.time()

        if not self._api_key:
            return SonarEnrichmentResult(
                status=SonarStatus.UNAVAILABLE,
                ttp_ids=ttp_ids,
                error_detail="No API key configured",
                enrichment_time_ms=0.0,
            )

        if not ttp_ids:
            return SonarEnrichmentResult(
                status=SonarStatus.SUCCESS,
                ttp_ids=[],
                raw_summary="No TTPs provided — nothing to enrich.",
                enrichment_time_ms=0.0,
            )

        prompt = self._build_enrichment_prompt(ttp_ids, context)

        try:
            raw = await self._call_sonar_with_retry(prompt)
        except Exception as exc:
            self._failed_calls += 1
            status = self._classify_error(exc)
            elapsed = (time.perf_counter() - start) * 1000
            logger.error(
                "sonar.enrichment_failed ttp_ids=%s status=%s error=%s elapsed_ms=%.2f",
                ttp_ids, status.value, str(exc), round(elapsed, 2),
            )
            return SonarEnrichmentResult(
                status=status,
                ttp_ids=ttp_ids,
                error_detail=str(exc),
                enrichment_time_ms=round(elapsed, 2),
            )

        # Parse the response
        result = self._parse_enrichment_response(raw, ttp_ids)
        result.enrichment_time_ms = round((time.perf_counter() - start) * 1000, 2)

        self._successful_calls += 1
        logger.info(
            "sonar.enrichment_complete ttp_ids=%s cves_found=%d campaigns_found=%d citations=%d elapsed_ms=%.2f",
            ttp_ids, len(result.cves), len(result.campaigns),
            len(result.citations), result.enrichment_time_ms,
        )

        return result

    async def assess_attack_novelty(
        self,
        attack_description: str,
        domain: str = "general",
    ) -> dict[str, Any]:
        """Query Sonar to assess whether an attack pattern matches recent campaigns.

        Used by EmberArmor's EnsembleConductor as a live-world consensus vote.
        Returns a structured verdict the conductor can interpret.

        Parameters
        ----------
        attack_description:
            Natural-language description of the flagged pattern (generated by
            EmberArmor's detector layer before calling Sonar).
        domain:
            Target domain context: ``legal``, ``financial``, ``medical``,
            or ``general``.

        Returns
        -------
        dict
            Keys: ``decision`` (SAFE/REVIEW/UNSAFE), ``confidence`` (0.0–1.0),
            ``reasoning`` (str), ``citations`` (list[str]),
            ``sonar_status`` (SonarStatus value).
        """
        start = time.perf_counter()
        self._total_calls += 1
        self._last_call_time = time.time()

        if not self._api_key:
            return {
                "decision": "REVIEW",
                "confidence": 0.0,
                "reasoning": "Sonar unavailable — no API key configured. Defaulting to REVIEW (fail-closed).",
                "citations": [],
                "sonar_status": SonarStatus.UNAVAILABLE.value,
            }

        prompt = self._build_novelty_prompt(attack_description, domain)

        try:
            raw = await self._call_sonar_with_retry(prompt)
        except Exception as exc:
            self._failed_calls += 1
            elapsed = (time.perf_counter() - start) * 1000
            status = self._classify_error(exc)
            logger.error(
                "sonar.novelty_check_failed domain=%s status=%s error=%s elapsed_ms=%.2f",
                domain, status.value, str(exc), round(elapsed, 2),
            )
            return {
                "decision": "REVIEW",
                "confidence": 0.0,
                "reasoning": f"Sonar error ({status.value}): {exc}. Defaulting to REVIEW.",
                "citations": [],
                "sonar_status": status.value,
            }

        verdict = self._parse_novelty_response(raw)
        verdict["sonar_status"] = SonarStatus.SUCCESS.value

        elapsed = (time.perf_counter() - start) * 1000
        self._successful_calls += 1
        logger.info(
            "sonar.novelty_check_complete decision=%s confidence=%s citations=%d elapsed_ms=%.2f",
            verdict["decision"], verdict["confidence"],
            len(verdict.get("citations", [])), round(elapsed, 2),
        )

        return verdict

    # ------------------------------------------------------------------
    # Internal prompt construction
    # ------------------------------------------------------------------

    def _build_enrichment_prompt(self, ttp_ids: list[str], context: str) -> str:
        ttp_list = ", ".join(ttp_ids)
        ctx_block = f"\n\nAdditional context from observed attacker behavior:\n{context}" if context else ""
        return (
            f"You are a threat intelligence analyst. For the following MITRE ATT&CK "
            f"technique IDs: {ttp_list} — provide:\n\n"
            f"1. Any CVEs disclosed in the last 30 days that are actively exploited "
            f"using these techniques. For each CVE include: CVE ID, severity (CRITICAL/"
            f"HIGH/MEDIUM/LOW), brief description, and whether a patch is available.\n\n"
            f"2. Known threat actor groups or campaigns observed in the last 7 days "
            f"using these techniques. For each campaign include: campaign/group name, "
            f"targeted sectors, and when last active.\n\n"
            f"Be concise and factual. Cite your sources."
            f"{ctx_block}"
        )

    def _build_novelty_prompt(self, attack_description: str, domain: str) -> str:
        domain_context = {
            "legal": "targeting legal firms, law practices, or court systems",
            "financial": "targeting financial institutions, trading systems, or fintech",
            "medical": "targeting healthcare providers, medical devices, or patient records",
            "general": "in enterprise environments",
        }.get(domain, "in enterprise environments")

        return (
            f"You are a threat intelligence analyst evaluating whether the following "
            f"AI system attack pattern matches any active, real-world adversarial "
            f"campaigns {domain_context}.\n\n"
            f"Attack pattern detected:\n{attack_description}\n\n"
            f"Answer these questions:\n"
            f"1. Has this type of attack been seen in real-world AI system compromises "
            f"in the last 30 days? (yes/no/unknown)\n"
            f"2. What is the current threat level for this pattern? (CRITICAL/HIGH/MEDIUM/LOW)\n"
            f"3. Should this be escalated immediately, flagged for review, or is it likely "
            f"benign? Respond with: UNSAFE / REVIEW / SAFE\n"
            f"4. Brief reasoning (2-3 sentences).\n\n"
            f"Be direct. Use recent sources. Cite them."
        )

    # ------------------------------------------------------------------
    # HTTP layer
    # ------------------------------------------------------------------

    async def _call_sonar_with_retry(self, prompt: str) -> dict[str, Any]:
        """Call Sonar with exponential backoff retry on transient errors."""
        last_exc: Exception | None = None

        for attempt in range(MAX_RETRIES + 1):
            if attempt > 0:
                await asyncio.sleep(RETRY_BACKOFF_SECONDS * attempt)
                logger.warning("sonar.retry attempt=%d", attempt)

            try:
                resp = await self._client.post(
                    SONAR_ENDPOINT,
                    json={
                        "model": self._model,
                        "messages": [
                            {
                                "role": "system",
                                "content": (
                                    "You are a cybersecurity threat intelligence analyst. "
                                    "Provide accurate, current, web-grounded analysis. "
                                    "Always cite sources."
                                ),
                            },
                            {"role": "user", "content": prompt},
                        ],
                        "search_recency_filter": CVE_SEARCH_RECENCY,
                        "return_related_questions": False,
                        "temperature": 0.1,    # Low temp — factual responses only
                    },
                )

                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 429:
                    raise _SonarRateLimitError(f"Rate limited: {resp.text}")
                elif resp.status_code in (401, 403):
                    raise _SonarAuthError(f"Auth error {resp.status_code}: {resp.text}")
                else:
                    raise _SonarAPIError(f"HTTP {resp.status_code}: {resp.text}")

            except (_SonarRateLimitError, _SonarAuthError):
                raise   # Don't retry auth/rate-limit errors
            except httpx.TimeoutException as exc:
                last_exc = exc
            except httpx.HTTPError as exc:
                last_exc = exc

        raise last_exc or _SonarAPIError("All retry attempts exhausted")

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_enrichment_response(
        self, raw: dict[str, Any], ttp_ids: list[str]
    ) -> SonarEnrichmentResult:
        """Parse a raw Sonar API response into structured enrichment data."""
        try:
            content: str = (
                raw.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
            )
            citations: list[str] = raw.get("citations", [])

            # Light parsing for CVE IDs mentioned in the response
            import re
            cve_ids = re.findall(r"CVE-\d{4}-\d{4,7}", content, re.IGNORECASE)
            cves = [
                CVERecord(
                    cve_id=cve_id.upper(),
                    description="See full Sonar response for details.",
                    severity=self._infer_severity(content, cve_id),
                    published_date="",
                    patch_available="patch" in content.lower() or "fix" in content.lower(),
                    source_url=citations[0] if citations else "",
                )
                for cve_id in set(cve_ids)
            ]

            # Light parsing for campaign mentions
            campaign_keywords = [
                "APT", "Lazarus", "Cobalt Strike", "RansomHub", "BlackCat",
                "LockBit", "Volt Typhoon", "Scattered Spider", "Salt Typhoon",
            ]
            campaigns = []
            for kw in campaign_keywords:
                if kw.lower() in content.lower():
                    campaigns.append(
                        CampaignRecord(
                            campaign_name=kw,
                            threat_actor=kw,
                            ttps_used=ttp_ids,
                            confidence=0.6,
                            source_url=citations[0] if citations else "",
                        )
                    )

            return SonarEnrichmentResult(
                status=SonarStatus.SUCCESS,
                ttp_ids=ttp_ids,
                cves=cves,
                campaigns=campaigns,
                raw_summary=content[:2000],     # Cap at 2KB for storage
                citations=citations,
            )

        except Exception as exc:
            logger.error("sonar.parse_failed error=%s", str(exc))
            return SonarEnrichmentResult(
                status=SonarStatus.ERROR,
                ttp_ids=ttp_ids,
                error_detail=f"Response parse error: {exc}",
            )

    def _parse_novelty_response(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Parse a novelty-check response into a consensus-compatible verdict."""
        try:
            content: str = (
                raw.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
            )
            citations: list[str] = raw.get("citations", [])

            content_upper = content.upper()

            # Extract decision signal
            if "UNSAFE" in content_upper:
                decision = "UNSAFE"
                confidence = 0.75
            elif "REVIEW" in content_upper:
                decision = "REVIEW"
                confidence = 0.6
            else:
                decision = "SAFE"
                confidence = 0.55

            # Boost confidence if Sonar found recent real-world examples
            if any(
                phrase in content.lower()
                for phrase in ["recently observed", "active campaign", "last month",
                               "this week", "currently being exploited", "in the wild"]
            ):
                confidence = min(0.95, confidence + 0.15)

            return {
                "decision": decision,
                "confidence": confidence,
                "reasoning": content[:500],     # First 500 chars for the audit log
                "citations": citations,
            }

        except Exception as exc:
            logger.error("sonar.novelty_parse_failed error=%s", str(exc))
            return {
                "decision": "REVIEW",
                "confidence": 0.0,
                "reasoning": f"Parse failed: {exc}",
                "citations": [],
            }

    @staticmethod
    def _infer_severity(content: str, cve_id: str) -> str:
        """Infer CVE severity from surrounding text context."""
        lower = content.lower()
        cve_pos = lower.find(cve_id.lower())
        if cve_pos == -1:
            return "UNKNOWN"
        window = lower[max(0, cve_pos - 200): cve_pos + 300]
        if "critical" in window:
            return "CRITICAL"
        if "high" in window:
            return "HIGH"
        if "medium" in window or "moderate" in window:
            return "MEDIUM"
        if "low" in window:
            return "LOW"
        return "UNKNOWN"

    @staticmethod
    def _classify_error(exc: Exception) -> SonarStatus:
        if isinstance(exc, _SonarRateLimitError):
            return SonarStatus.RATE_LIMITED
        if isinstance(exc, _SonarAuthError):
            return SonarStatus.INVALID_KEY
        if isinstance(exc, httpx.TimeoutException):
            return SonarStatus.TIMEOUT
        return SonarStatus.ERROR

    # ------------------------------------------------------------------
    # Health / telemetry
    # ------------------------------------------------------------------

    @property
    def stats(self) -> dict[str, Any]:
        """Return telemetry stats for monitoring dashboards."""
        total = max(1, self._total_calls)
        return {
            "total_calls": self._total_calls,
            "successful_calls": self._successful_calls,
            "failed_calls": self._failed_calls,
            "success_rate": round(self._successful_calls / total, 4),
            "model": self._model,
            "last_call_time": self._last_call_time,
            "api_key_configured": bool(self._api_key),
        }


# ---------------------------------------------------------------------------
# Private exception types
# ---------------------------------------------------------------------------

class _SonarRateLimitError(Exception):
    """Raised on HTTP 429 from Sonar."""


class _SonarAuthError(Exception):
    """Raised on HTTP 401/403 from Sonar."""


class _SonarAPIError(Exception):
    """Raised on other non-200 responses from Sonar."""


# ---------------------------------------------------------------------------
# Module-level convenience client (lazy-initialized from env)
# ---------------------------------------------------------------------------

_default_client: SonarIntelligenceClient | None = None


def get_sonar_client() -> SonarIntelligenceClient:
    """Return (or create) the module-level Sonar client.

    The client is initialized once and reused. API key is read from the
    ``PERPLEXITY_API_KEY`` environment variable.
    """
    global _default_client
    if _default_client is None:
        _default_client = SonarIntelligenceClient()
    return _default_client
