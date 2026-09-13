"""
Lexical / information-theoretic features.

This is the mathematical heart of tunnelling + DGA detection. A human-registered
domain is a *low-entropy, pronounceable, dictionary-adjacent* string. An
encoded payload or an algorithmically generated domain is not.

Nothing here needs network access, a GPU, or a paid feed — it is all pure
information theory over the query string.
"""

from __future__ import annotations

import math
import re
import zlib
from collections import Counter
from functools import lru_cache

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")
HEX_CHARS = set("0123456789abcdef")
B32_CHARS = set("abcdefghijklmnopqrstuvwxyz234567=")
B64_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=-_")

# English letter frequencies (%) — used for the chi-square "does this look like
# language?" statistic.
_ENGLISH_FREQ = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702, "f": 2.228,
    "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153, "k": 0.772, "l": 4.025,
    "m": 2.406, "n": 6.749, "o": 7.507, "p": 1.929, "q": 0.095, "r": 5.987,
    "s": 6.327, "t": 9.056, "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150,
    "y": 1.974, "z": 0.074,
}

# A compact, high-value word list: the substrings that show up in the overwhelming
# majority of legitimate hostnames. Keeping it small keeps the project
# dependency-free and fast — no 200 MB corpus download required.
_COMMON_TOKENS = frozenset("""  # noqa: SIM905
api cdn www mail smtp imap pop ns dns mx web app static assets img image
images video media cloud storage bucket s3 blob edge node host server
client login auth oauth sso account accounts user users admin portal
dashboard console panel shop store cart checkout pay payment billing
invoice secure ssl vpn proxy gateway gw git repo code build ci cd deploy
release stage staging prod production dev test qa uat demo sandbox beta
alpha internal intranet corp office hr finance sales support help docs doc
wiki blog news forum chat talk meet zoom teams slack track analytics
metrics stats log logs monitor health status ping time ntp update updates
download downloads upload uploads file files share drive sync backup
search query find map maps geo location weather mobile android ios play
market ads ad banner pixel tag click link short url redirect www2 www3
origin cache front back end service svc micro api1 api2 v1 v2 v3 rest
graphql grpc socket ws
""".split())

_LABEL_SPLIT = re.compile(r"[.\-_]")


# --------------------------------------------------------------------------- #
# Entropy family
# --------------------------------------------------------------------------- #
def shannon_entropy(s: str) -> float:
    """H(X) = -Σ p(x) log2 p(x).  Bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def normalized_entropy(s: str) -> float:
    """Entropy scaled by the maximum possible for that string length (0..1)."""
    if len(s) < 2:
        return 0.0
    max_h = math.log2(min(len(s), len(set(s)))) or 1.0
    return shannon_entropy(s) / max_h if max_h else 0.0


def renyi_entropy(s: str, alpha: float = 2.0) -> float:
    """Rényi entropy — alpha=2 (collision entropy) is very sensitive to
    the flat character distributions produced by base32/base64 encoders."""
    if not s or alpha == 1.0:
        return shannon_entropy(s)
    n = len(s)
    probs = [c / n for c in Counter(s).values()]
    total = sum(p ** alpha for p in probs)
    return (1.0 / (1.0 - alpha)) * math.log2(total) if total > 0 else 0.0


def min_entropy(s: str) -> float:
    """H_inf = -log2(max p(x)). Low for text, high for uniform payloads."""
    if not s:
        return 0.0
    n = len(s)
    p_max = max(Counter(s).values()) / n
    return -math.log2(p_max)


def conditional_entropy(s: str) -> float:
    """Empirical second-order entropy H(X_n | X_{n-1}).

    Honest caveat: over a 20-60 character hostname this is a *bigram
    repetition* statistic, not a true entropy rate — a string whose bigrams are
    all unique yields exactly 0, which is the opposite of what a naive reading
    suggests. It is kept because repetition is genuinely informative, but the
    heavy lifting for "does this look like language?" is done by
    `ngram_coverage` and `ngram_score` below, which compare against an external
    model of real hostnames instead of the string's own statistics.
    """
    if len(s) < 3:
        return 0.0
    bigrams = Counter(s[i:i + 2] for i in range(len(s) - 1))
    unigrams = Counter(s[:-1])
    total = sum(bigrams.values())
    h = 0.0
    for bg, cnt in bigrams.items():
        p_xy = cnt / total
        p_x = unigrams[bg[0]] / total
        if p_x > 0:
            h -= p_xy * math.log2(p_xy / p_x)
    return h


def compression_ratio(s: str) -> float:
    """A cheap Kolmogorov-complexity proxy. Incompressible ⇒ encoded payload."""
    if len(s) < 8:
        return 1.0
    raw = s.encode("utf-8", "ignore")
    comp = zlib.compress(raw, 9)
    return len(comp) / len(raw)


def index_of_coincidence(s: str) -> float:
    """Classic cryptanalysis statistic. English ≈ 0.066, random ≈ 0.038."""
    letters = [c for c in s if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def chi_square_english(s: str) -> float:
    """Goodness-of-fit against English letter frequency. Big ⇒ not language."""
    letters = [c for c in s.lower() if c in _ENGLISH_FREQ]
    n = len(letters)
    if n < 4:
        return 0.0
    counts = Counter(letters)
    chi = 0.0
    for ch, pct in _ENGLISH_FREQ.items():
        expected = n * pct / 100.0
        observed = counts.get(ch, 0)
        chi += (observed - expected) ** 2 / expected
    return chi / n  # length-normalised so short/long domains compare fairly


# --------------------------------------------------------------------------- #
# N-gram language model (built from the token list — zero download)
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def _ngram_model() -> tuple[dict[str, float], dict[str, float], float, float]:
    """Log-probability tables for bigrams and trigrams of 'normal' hostnames."""
    corpus = " ".join(sorted(_COMMON_TOKENS)) + " " + " ".join(_ENGLISH_FREQ)
    bi: Counter[str] = Counter()
    tri: Counter[str] = Counter()
    for token in corpus.split():
        padded = f"^{token}$"
        for i in range(len(padded) - 1):
            bi[padded[i:i + 2]] += 1
        for i in range(len(padded) - 2):
            tri[padded[i:i + 3]] += 1
    bi_total = sum(bi.values()) or 1
    tri_total = sum(tri.values()) or 1
    bi_lp = {k: math.log2(v / bi_total) for k, v in bi.items()}
    tri_lp = {k: math.log2(v / tri_total) for k, v in tri.items()}
    # Smoothing floors for unseen n-grams.
    return bi_lp, tri_lp, math.log2(1 / (bi_total * 10)), math.log2(1 / (tri_total * 10))


def ngram_score(s: str, n: int = 2) -> float:
    """Mean log-probability of the string under the hostname n-gram model.

    Closer to 0 = looks like a real hostname. Very negative = gibberish.
    """
    if len(s) < n:
        return 0.0
    bi_lp, tri_lp, bi_floor, tri_floor = _ngram_model()
    table, floor = (bi_lp, bi_floor) if n == 2 else (tri_lp, tri_floor)
    padded = f"^{s}$"
    grams = [padded[i:i + n] for i in range(len(padded) - n + 1)]
    if not grams:
        return 0.0
    return sum(table.get(g, floor) for g in grams) / len(grams)


def ngram_coverage(s: str, n: int = 2) -> float:
    """Fraction of the string's n-grams that exist in the hostname model.

    This is the principled version of "does this look like a real hostname":
    it compares against an *external* reference distribution instead of the
    string's own statistics, so it stays meaningful at any length. Real
    hostnames reuse the same letter pairs over and over; base32 payloads and
    DGA output produce combinations that simply never occur in names humans
    chose.
    """
    if len(s) < n:
        return 0.0
    bi_lp, tri_lp, _, _ = _ngram_model()
    table = bi_lp if n == 2 else tri_lp
    grams = [s[i:i + n] for i in range(len(s) - n + 1)]
    if not grams:
        return 0.0
    return sum(1 for g in grams if g in table) / len(grams)


def unique_ngram_ratio(s: str, n: int = 2) -> float:
    """Fraction of n-grams that occur exactly once — high for random strings."""
    if len(s) < n + 1:
        return 0.0
    grams = [s[i:i + n] for i in range(len(s) - n + 1)]
    return len(set(grams)) / len(grams)


# --------------------------------------------------------------------------- #
# Character-class + morphology
# --------------------------------------------------------------------------- #
def _ratio(pred, s: str) -> float:
    return (sum(1 for c in s if pred(c)) / len(s)) if s else 0.0


def max_consecutive(s: str, charset: set[str]) -> int:
    best = run = 0
    for c in s:
        run = run + 1 if c in charset else 0
        best = max(best, run)
    return best


def longest_repeated_substring_ratio(s: str) -> float:
    """Length of the longest substring occurring twice, over total length."""
    n = len(s)
    if n < 4:
        return 0.0
    best = 0
    for length in range(min(n // 2, 12), 1, -1):
        seen: set[str] = set()
        for i in range(n - length + 1):
            chunk = s[i:i + length]
            if chunk in seen:
                best = length
                break
            seen.add(chunk)
        if best:
            break
    return best / n


def dictionary_hit_ratio(s: str) -> float:
    """How much of the string is made of recognisable hostname vocabulary."""
    if not s:
        return 0.0
    tokens = [t for t in _LABEL_SPLIT.split(s) if t]
    if not tokens:
        return 0.0
    hits = 0
    for tok in tokens:
        if tok in _COMMON_TOKENS:
            hits += 1
        elif any(w in tok for w in _COMMON_TOKENS if len(w) >= 4):
            hits += 0.5
    return min(hits / len(tokens), 1.0)


def charset_conformance(s: str, charset: set[str]) -> float:
    """Fraction of characters belonging to an encoding alphabet (hex/b32/b64)."""
    return _ratio(lambda c: c in charset, s)


def transition_rate(s: str) -> float:
    """How often the character class flips (letter→digit→letter…).

    Encoders interleave classes far more than human names do.
    """
    if len(s) < 2:
        return 0.0
    def cls(c: str) -> int:
        return 0 if c.isdigit() else (1 if c.isalpha() else 2)
    flips = sum(1 for i in range(1, len(s)) if cls(s[i]) != cls(s[i - 1]))
    return flips / (len(s) - 1)


def digit_position_bias(s: str) -> float:
    """Mean normalised position of digits. DGAs scatter digits uniformly;
    real hostnames put them at the end ('api2', 'www3')."""
    positions = [i / max(len(s) - 1, 1) for i, c in enumerate(s) if c.isdigit()]
    return sum(positions) / len(positions) if positions else 0.0


# --------------------------------------------------------------------------- #
# Public: extract the whole lexical block for one string
# --------------------------------------------------------------------------- #
def lexical_features(qname: str, subdomain: str) -> dict[str, float]:
    """~45 lexical features computed over the full name and the subdomain."""
    labels = [x for x in qname.split(".") if x]
    longest = max(labels, key=len) if labels else ""
    flat = qname.replace(".", "")
    sub_flat = subdomain.replace(".", "")
    # The part an attacker actually controls. A very short subdomain ("www",
    # "api") carries no statistical signal and would produce nonsense ratios,
    # so below 6 characters we fall back to the whole name.
    target = sub_flat if len(sub_flat) >= 6 else flat

    f: dict[str, float] = {}

    # --- Entropy family (10) ------------------------------------------------
    f["shannon_entropy_full"] = shannon_entropy(flat)
    f["shannon_entropy_sub"] = shannon_entropy(sub_flat)
    f["shannon_entropy_longest"] = shannon_entropy(longest)
    f["normalized_entropy_full"] = normalized_entropy(flat)
    f["normalized_entropy_sub"] = normalized_entropy(sub_flat)
    f["renyi_entropy_2"] = renyi_entropy(target, 2.0)
    f["renyi_entropy_05"] = renyi_entropy(target, 0.5)
    f["min_entropy"] = min_entropy(target)
    f["conditional_entropy"] = conditional_entropy(target)
    f["entropy_per_label"] = (
        sum(shannon_entropy(x) for x in labels) / len(labels) if labels else 0.0
    )

    # --- Complexity / randomness (6) ---------------------------------------
    f["compression_ratio"] = compression_ratio(target)
    f["compression_ratio_full"] = compression_ratio(flat)
    f["index_of_coincidence"] = index_of_coincidence(target)
    f["chi_square_english"] = chi_square_english(target)
    f["unique_char_ratio"] = len(set(target)) / len(target) if target else 0.0
    f["longest_repeat_ratio"] = longest_repeated_substring_ratio(target)

    # --- N-gram language model (6) -----------------------------------------
    f["bigram_logprob"] = ngram_score(target, 2)
    f["trigram_logprob"] = ngram_score(target, 3)
    f["bigram_logprob_longest"] = ngram_score(longest, 2)
    f["unique_bigram_ratio"] = unique_ngram_ratio(target, 2)
    f["unique_trigram_ratio"] = unique_ngram_ratio(target, 3)
    f["bigram_coverage"] = ngram_coverage(target, 2)
    f["trigram_coverage"] = ngram_coverage(target, 3)
    f["dictionary_hit_ratio"] = dictionary_hit_ratio(qname)

    # --- Character class ratios (11) ---------------------------------------
    f["digit_ratio"] = _ratio(str.isdigit, target)
    f["alpha_ratio"] = _ratio(str.isalpha, target)
    f["vowel_ratio"] = _ratio(lambda c: c in VOWELS, target)
    f["consonant_ratio"] = _ratio(lambda c: c in CONSONANTS, target)
    f["hyphen_ratio"] = _ratio(lambda c: c == "-", qname)
    f["special_ratio"] = _ratio(lambda c: not c.isalnum(), target)
    f["uppercase_ratio"] = _ratio(str.isupper, qname)
    vowels = sum(1 for c in target if c in VOWELS)
    consonants = sum(1 for c in target if c in CONSONANTS)
    f["vowel_consonant_ratio"] = vowels / consonants if consonants else 0.0
    f["hex_conformance"] = charset_conformance(target, HEX_CHARS)
    f["base32_conformance"] = charset_conformance(target, B32_CHARS)
    f["base64_conformance"] = charset_conformance(target, B64_CHARS)

    # --- Morphology (8) -----------------------------------------------------
    f["max_consec_consonants"] = float(max_consecutive(target, CONSONANTS))
    f["max_consec_digits"] = float(max_consecutive(target, set("0123456789")))
    f["max_consec_vowels"] = float(max_consecutive(target, VOWELS))
    f["transition_rate"] = transition_rate(target)
    f["digit_position_bias"] = digit_position_bias(target)
    f["starts_with_digit"] = 1.0 if target[:1].isdigit() else 0.0
    f["has_punycode"] = 1.0 if "xn--" in qname else 0.0
    f["repeated_char_max"] = float(
        max((len(list(g)) for g in _runs(target)), default=0)
    )

    # --- Cross-part contrast (3) -------------------------------------------
    # A legitimate CDN hostname has a *uniform* entropy profile across its
    # labels. Tunnelling grafts a high-entropy payload onto a low-entropy
    # registered domain, producing a large gap — a very robust signal that
    # survives the attacker changing their encoding alphabet.
    reg_flat = "".join(labels[-2:])
    f["entropy_gap_sub_vs_reg"] = shannon_entropy(sub_flat) - shannon_entropy(reg_flat)
    label_entropies = [shannon_entropy(x) for x in labels] or [0.0]
    f["label_entropy_std"] = (
        (sum((x - sum(label_entropies) / len(label_entropies)) ** 2
             for x in label_entropies) / len(label_entropies)) ** 0.5
    )
    f["label_entropy_max"] = max(label_entropies)

    return f


def _runs(s: str):
    """Yield runs of identical characters (helper for repeated_char_max)."""
    if not s:
        return
    cur = s[0]
    run = [cur]
    for c in s[1:]:
        if c == cur:
            run.append(c)
        else:
            yield run
            cur, run = c, [c]
    yield run
