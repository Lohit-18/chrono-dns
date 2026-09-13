"""
Structural features — the *shape* of the query and the record type abused.

DNS tunnelling tools (iodine, dnscat2, dns2tcp, DNSExfiltrator) are forced by
the protocol into recognisable shapes:

  * RFC 1035 caps a label at 63 bytes and a name at 255 bytes, so tunnels
    max out those limits to maximise per-query bandwidth.
  * They prefer TXT / NULL / CNAME because those carry the most downstream data.
  * They use many labels or one very long label.
"""

from __future__ import annotations

import statistics

# Record types weighted by how unusual they are in normal enterprise traffic
# and how much payload they can carry. 1.0 = maximum abuse potential.
QTYPE_RISK = {
    "A": 0.05, "AAAA": 0.05, "PTR": 0.10, "MX": 0.25, "NS": 0.30,
    "SOA": 0.20, "SRV": 0.20, "HTTPS": 0.05, "SVCB": 0.05, "CAA": 0.15,
    "CNAME": 0.55, "TXT": 0.90, "NULL": 1.00, "ANY": 0.85, "AXFR": 0.95,
    "DNSKEY": 0.40, "RRSIG": 0.35, "NAPTR": 0.60, "KEY": 0.70, "SPF": 0.35,
}
DEFAULT_QTYPE_RISK = 0.50

# TLDs disproportionately represented in malware C2 / abuse reporting.
# (Static, offline scoring table — no paid feed needed.)
TLD_RISK = {
    "com": 0.05, "net": 0.08, "org": 0.08, "io": 0.12, "dev": 0.10,
    "edu": 0.02, "gov": 0.02, "mil": 0.02, "int": 0.05, "co": 0.15,
    "uk": 0.06, "de": 0.06, "fr": 0.07, "jp": 0.05, "in": 0.10,
    "info": 0.45, "biz": 0.45, "xyz": 0.70, "top": 0.80, "click": 0.80,
    "link": 0.70, "work": 0.70, "gq": 0.90, "ml": 0.90, "cf": 0.90,
    "ga": 0.90, "tk": 0.95, "zip": 0.75, "mov": 0.70, "su": 0.80,
    "ru": 0.55, "cn": 0.50, "pw": 0.80, "cc": 0.55, "ws": 0.60,
    "buzz": 0.75, "rest": 0.70, "monster": 0.85, "cyou": 0.85, "bar": 0.70,
    "surf": 0.75, "quest": 0.80, "fit": 0.65, "loan": 0.85, "download": 0.85,
}
DEFAULT_TLD_RISK = 0.35

MAX_LABEL_LEN = 63       # RFC 1035 §2.3.4
MAX_NAME_LEN = 253       # 255 wire bytes minus root + length prefix


def structural_features(qname: str, qtype: str, subdomain: str,
                        payload_size: int = 0, transport: str = "udp") -> dict[str, float]:
    """~25 structural features."""
    labels = [x for x in qname.split(".") if x]
    label_lens = [len(x) for x in labels] or [0]
    sub_labels = [x for x in subdomain.split(".") if x]
    tld = labels[-1] if labels else ""
    qt = (qtype or "A").upper()

    f: dict[str, float] = {}

    # --- Size / geometry (10) ----------------------------------------------
    f["qname_length"] = float(len(qname))
    f["qname_length_ratio"] = len(qname) / MAX_NAME_LEN
    f["label_count"] = float(len(labels))
    f["sub_label_count"] = float(len(sub_labels))
    f["subdomain_length"] = float(len(subdomain))
    f["subdomain_share"] = len(subdomain) / len(qname) if qname else 0.0
    f["max_label_length"] = float(max(label_lens))
    f["min_label_length"] = float(min(label_lens))
    f["mean_label_length"] = float(statistics.fmean(label_lens))
    f["std_label_length"] = float(statistics.pstdev(label_lens)) if len(label_lens) > 1 else 0.0

    # --- RFC limit pressure (4) — tunnels sit right at the ceiling ----------
    f["label_len_saturation"] = max(label_lens) / MAX_LABEL_LEN
    f["at_label_limit"] = 1.0 if max(label_lens) >= MAX_LABEL_LEN - 2 else 0.0
    f["near_name_limit"] = 1.0 if len(qname) >= MAX_NAME_LEN - 20 else 0.0
    f["long_label_count"] = float(sum(1 for x in label_lens if x > 30))

    # --- Record type (6) ----------------------------------------------------
    f["qtype_risk"] = QTYPE_RISK.get(qt, DEFAULT_QTYPE_RISK)
    f["is_txt"] = 1.0 if qt == "TXT" else 0.0
    f["is_null"] = 1.0 if qt == "NULL" else 0.0
    f["is_cname"] = 1.0 if qt == "CNAME" else 0.0
    f["is_any"] = 1.0 if qt == "ANY" else 0.0
    f["is_high_capacity_type"] = 1.0 if qt in ("TXT", "NULL", "CNAME", "ANY", "NAPTR") else 0.0

    # --- Zone / TLD reputation (4) -----------------------------------------
    f["tld_risk"] = TLD_RISK.get(tld, DEFAULT_TLD_RISK)
    f["tld_length"] = float(len(tld))
    f["is_numeric_tld"] = 1.0 if tld.isdigit() else 0.0
    f["numeric_label_count"] = float(sum(1 for x in labels if x.isdigit()))

    # --- Transport / payload (3) -------------------------------------------
    f["payload_size"] = float(payload_size)
    f["is_tcp"] = 1.0 if transport == "tcp" else 0.0
    f["bytes_per_label"] = len(qname) / len(labels) if labels else 0.0

    return f
