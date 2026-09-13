"""
Deterministic expert rules — the third voter in the ensemble.

Why keep hand-written rules when you have a Random Forest? Three reasons that
matter in a real deployment:

  1. **Cold start.** Before a model is trained, the gateway still has to make
     decisions. Heuristics give a usable day-zero product.
  2. **Explainability.** "Blocked: 61-byte base32 label on a TXT record" is an
     answer an auditor accepts. "Blocked: p=0.94" is not.
  3. **Adversarial floor.** An attacker who reverse-engineers the model still
     cannot push a 63-byte high-entropy label past a hard rule.

Each rule returns (weight, reason). Weights are summed and squashed, so several
weak signals can combine into a strong one — the same additive-evidence logic
a human analyst uses.
"""

from __future__ import annotations

import math

RULES_DOC = [
    ("high_subdomain_entropy", "Subdomain entropy > 3.6 bits/char"),
    ("label_at_rfc_limit", "A label is within 2 bytes of the 63-byte RFC 1035 cap"),
    ("encoded_alphabet", "Charset conforms to base32/base64/hex AND entropy is high"),
    ("high_capacity_qtype", "TXT / NULL / ANY record — maximum payload capacity"),
    ("unpronounceable", "Very low vowel ratio and long consonant runs"),
    ("ngram_implausible", "Trigram log-probability far below hostname norms"),
    ("beacon_lockstep", "Inter-arrival CV below 0.10 over 6+ samples"),
    ("zone_novelty_storm", "Near-100% unique subdomains under one zone"),
    ("upload_rate", "Sustained subdomain byte-rate consistent with file transfer"),
    ("nxdomain_burst", "NXDOMAIN storm from one host"),
    ("risky_tld", "TLD with a high documented abuse rate"),
    ("long_name_no_dictionary", "Long name with no recognisable vocabulary"),
]


def heuristic_score(f: dict[str, float]) -> tuple[float, list[str]]:
    """Return (0..1 score, reasons)."""
    evidence = 0.0
    reasons: list[str] = []

    def add(weight: float, reason: str) -> None:
        nonlocal evidence
        evidence += weight
        reasons.append(reason)

    sub_h = f.get("shannon_entropy_sub", 0.0)
    full_h = f.get("shannon_entropy_full", 0.0)
    sub_len = f.get("subdomain_length", 0.0)

    # --- 1. Entropy -------------------------------------------------------
    if sub_h > 4.2 and sub_len >= 20:
        add(2.2, f"very high subdomain entropy {sub_h:.2f} bits/char over {int(sub_len)}B")
    elif sub_h > 3.6 and sub_len >= 16:
        add(1.3, f"high subdomain entropy {sub_h:.2f} bits/char")
    elif full_h > 4.0 and f.get("qname_length", 0) > 40:
        add(0.9, f"high overall entropy {full_h:.2f} on a long name")

    # --- 2. RFC limit pressure -------------------------------------------
    if f.get("at_label_limit", 0.0) >= 1.0:
        add(1.8, "label pinned at the 63-byte RFC 1035 ceiling")
    elif f.get("label_len_saturation", 0.0) > 0.7:
        add(0.8, f"label {int(f.get('max_label_length', 0))}B — {f['label_len_saturation']:.0%} of the RFC cap")
    if f.get("near_name_limit", 0.0) >= 1.0:
        add(1.0, "query name near the 253-byte wire limit")

    # --- 3. Encoding alphabets -------------------------------------------
    b32 = f.get("base32_conformance", 0.0)
    hexc = f.get("hex_conformance", 0.0)
    if b32 > 0.97 and sub_h > 3.8 and sub_len > 24:
        add(1.6, f"pure base32 alphabet across {int(sub_len)}B — encoded payload")
    elif hexc > 0.97 and sub_len > 20:
        add(1.2, f"pure hex alphabet across {int(sub_len)}B")
    if f.get("compression_ratio", 1.0) > 1.05 and sub_len > 24:
        add(0.7, "payload is incompressible — not natural language")

    # --- 4. Record type ---------------------------------------------------
    if f.get("is_null", 0.0) >= 1.0:
        add(1.7, "NULL record — almost never legitimate")
    elif f.get("is_txt", 0.0) >= 1.0 and sub_h > 3.2:
        add(1.1, "TXT record carrying a high-entropy label")
    elif f.get("is_any", 0.0) >= 1.0:
        add(0.8, "ANY query — reconnaissance or tunnelling")

    # --- 5. Linguistic implausibility (DGA) -------------------------------
    if f.get("vowel_consonant_ratio", 1.0) < 0.18 and f.get("qname_length", 0) > 10:
        add(1.2, f"unpronounceable: vowel/consonant {f['vowel_consonant_ratio']:.2f}")
    if f.get("max_consec_consonants", 0.0) >= 6:
        add(0.9, f"{int(f['max_consec_consonants'])} consecutive consonants")
    if f.get("trigram_logprob", 0.0) < -13.5:
        add(1.0, f"trigram log-prob {f['trigram_logprob']:.1f} — not a plausible hostname")
    if f.get("dictionary_hit_ratio", 1.0) < 0.05 and f.get("qname_length", 0) > 14:
        add(0.6, "no recognisable hostname vocabulary")

    # --- 6. Temporal: beaconing -------------------------------------------
    cv = f.get("iat_cv", 99.0)
    samples = f.get("zone_query_count", 0.0)
    if samples >= 6 and 0 < cv < 0.05:
        add(2.0, f"lockstep timing: CV={cv:.3f} over {int(samples)} queries")
    elif samples >= 6 and cv < 0.12:
        add(1.3, f"low-jitter beacon: CV={cv:.3f}, period ~{f.get('beacon_period_s', 0):.0f}s")
    elif samples >= 8 and f.get("beacon_strength", 0.0) > 0.85:
        add(0.9, f"strong periodicity {f['beacon_strength']:.2f}")

    # --- 7. Temporal: tunnelling volume ------------------------------------
    novelty = f.get("zone_sub_novelty", 0.0)
    if samples >= 15 and novelty > 0.95 and sub_h > 3.0:
        add(1.9, f"{int(f.get('zone_unique_subs', 0))} unique subdomains under one zone ({novelty:.0%} novel)")
    if f.get("zone_upload_rate", 0.0) > 120:
        add(1.5, f"{f['zone_upload_rate']:.0f} B/s of subdomain data — file transfer rate")
    elif f.get("zone_upload_rate", 0.0) > 40:
        add(0.7, f"{f['zone_upload_rate']:.0f} B/s sustained subdomain upload")

    # --- 8. Host-level volumetrics -----------------------------------------
    if f.get("host_nxdomain_60s", 0.0) > 25:
        add(1.4, f"{int(f['host_nxdomain_60s'])} NXDOMAINs in 60s — DGA storm")
    if f.get("host_qps_10s", 0.0) > 25:
        add(0.8, f"{f['host_qps_10s']:.0f} queries/s from one host")

    # --- 9. Zone reputation -------------------------------------------------
    tld_risk = f.get("tld_risk", 0.0)
    if tld_risk > 0.75:
        add(0.9, f"TLD abuse score {tld_risk:.2f}")
    elif tld_risk > 0.55:
        add(0.4, f"elevated TLD abuse score {tld_risk:.2f}")

    # --- squash: 0 evidence -> 0.0, ~6 units of evidence -> ~0.95 ----------
    score = 1.0 - math.exp(-evidence / 2.6)
    return min(max(score, 0.0), 1.0), reasons


def classify_by_rules(f: dict[str, float]) -> str:
    """Cheap threat-class guess used when the ML model is unavailable."""
    cv = f.get("iat_cv", 99.0)
    samples = f.get("zone_query_count", 0.0)
    if samples >= 6 and cv < 0.12:
        return "c2_beacon"
    if (f.get("subdomain_length", 0) > 24 and f.get("shannon_entropy_sub", 0) > 3.4) \
            or f.get("at_label_limit", 0) >= 1.0:
        return "tunneling"
    if f.get("trigram_logprob", 0) < -13.0 and f.get("label_count", 0) <= 3 \
            and f.get("vowel_consonant_ratio", 1) < 0.35:
        return "dga"
    return "benign"
