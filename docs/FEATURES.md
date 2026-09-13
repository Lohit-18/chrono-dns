# Feature reference

**104 features** per DNS query, in a frozen order — a model trained today
still lines up with a gateway running next year. Adding a feature is a model-version bump.

This page is generated from the extractor itself. Regenerate the same content in your
terminal with:

```bash
chronodns features
```

| Group | Count | What it captures |
|---|---:|---|
| [Lexical](#lexical) | 46 | Information theory over the query string |
| [Structural](#structural) | 27 | Query shape and the record type abused |
| [Temporal](#temporal) | 31 | Rolling per-host and per-zone behaviour |

---

## Lexical

*46 features*

Computed over the whole name, the attacker-controlled subdomain and the longest
label. Where the subdomain is shorter than 6 characters (`www`, `api`) the whole
name is used instead, because a 3-character string carries no statistical signal.

None of these need network access, a GPU or a paid feed — it is pure information
theory over the query string.

| # | Feature | Meaning |
|---:|---|---|
| 1 | `shannon_entropy_full` | Bits/char over the whole name — the core tunnelling signal |
| 2 | `shannon_entropy_sub` | Entropy of the attacker-controlled subdomain only |
| 3 | `shannon_entropy_longest` | Entropy of the single longest label |
| 4 | `normalized_entropy_full` | Entropy scaled by the maximum possible for that length |
| 5 | `normalized_entropy_sub` | Same, over the attacker-controlled subdomain |
| 6 | `renyi_entropy_2` | Collision entropy; very sensitive to flat encoder alphabets |
| 7 | `renyi_entropy_05` | Rényi alpha=0.5; weights rare characters more heavily |
| 8 | `min_entropy` | -log2 of the most frequent character's probability |
| 9 | `conditional_entropy` | H(Xn|Xn-1); real words are predictable, payloads are not |
| 10 | `entropy_per_label` | Mean entropy across the individual labels |
| 11 | `compression_ratio` | zlib size ratio — incompressible means encoded data |
| 12 | `compression_ratio_full` | zlib ratio over the whole name |
| 13 | `index_of_coincidence` | Cryptanalytic IC; English ~0.066, random ~0.038 |
| 14 | `chi_square_english` | Goodness of fit to English letter frequencies |
| 15 | `unique_char_ratio` | Distinct characters over length |
| 16 | `longest_repeat_ratio` | Longest substring occurring twice, over length |
| 17 | `bigram_logprob` | Mean log-probability under a hostname bigram model |
| 18 | `trigram_logprob` | Same, trigram order — strongest DGA discriminator |
| 19 | `bigram_logprob_longest` | Bigram plausibility of the longest label alone |
| 20 | `unique_bigram_ratio` | Share of letter pairs occurring exactly once |
| 21 | `unique_trigram_ratio` | Share of letter triples occurring exactly once |
| 22 | `bigram_coverage` | Fraction of letter pairs that exist in real hostnames |
| 23 | `trigram_coverage` | Fraction of letter triples that exist in real hostnames |
| 24 | `dictionary_hit_ratio` | Share of labels that are real hostname vocabulary |
| 25 | `digit_ratio` | Share of digits |
| 26 | `alpha_ratio` | Share of letters |
| 27 | `vowel_ratio` | Share of vowels |
| 28 | `consonant_ratio` | Share of consonants |
| 29 | `hyphen_ratio` | Share of hyphens in the full name |
| 30 | `special_ratio` | Share of non-alphanumeric characters |
| 31 | `uppercase_ratio` | Share of uppercase characters (0-day mixed-case tricks) |
| 32 | `vowel_consonant_ratio` | DGA output is consonant-heavy and unpronounceable |
| 33 | `hex_conformance` | Fraction of chars inside the hex alphabet |
| 34 | `base32_conformance` | Fraction of chars inside the base32 alphabet |
| 35 | `base64_conformance` | Fraction of chars inside the base64url alphabet |
| 36 | `max_consec_consonants` | Longest unpronounceable run |
| 37 | `max_consec_digits` | Longest digit run |
| 38 | `max_consec_vowels` | Longest vowel run |
| 39 | `transition_rate` | How often the character class flips (encoder tell) |
| 40 | `digit_position_bias` | Mean normalised position of digits; real names put them last |
| 41 | `starts_with_digit` | Binary: first character is a digit |
| 42 | `has_punycode` | Binary: contains an xn-- IDN prefix |
| 43 | `repeated_char_max` | Longest run of one repeated character |
| 44 | `entropy_gap_sub_vs_reg` | Entropy of the subdomain minus that of the registered zone |
| 45 | `label_entropy_std` | Spread of per-label entropy; tunnels graft high onto low |
| 46 | `label_entropy_max` | Highest per-label entropy |

---

## Structural

*27 features*

RFC 1035 caps a label at 63 bytes and a name at 253. Tunnelling tools maximise
per-query bandwidth, so they sit right at those ceilings, and they prefer the
record types that carry the most data downstream (TXT, NULL, CNAME).

| # | Feature | Meaning |
|---:|---|---|
| 1 | `qname_length` | Total query name length in bytes |
| 2 | `qname_length_ratio` | Name length over the 253-byte wire limit |
| 3 | `label_count` | Number of dot-separated labels |
| 4 | `sub_label_count` | Labels belonging to the subdomain |
| 5 | `subdomain_length` | Bytes the attacker controls |
| 6 | `subdomain_share` | How much of the name the attacker controls |
| 7 | `max_label_length` | Longest label in bytes |
| 8 | `min_label_length` | Shortest label in bytes |
| 9 | `mean_label_length` | Mean label length |
| 10 | `std_label_length` | Spread of label lengths |
| 11 | `label_len_saturation` | Longest label / 63 — tunnels sit at the RFC ceiling |
| 12 | `at_label_limit` | Binary: a label is within 2 bytes of the 63-byte cap |
| 13 | `near_name_limit` | Binary: within 20 bytes of the 253-byte wire limit |
| 14 | `long_label_count` | Number of labels longer than 30 bytes |
| 15 | `qtype_risk` | Payload capacity + rarity of the record type |
| 16 | `is_txt` | TXT records carry the most data — heavily abused |
| 17 | `is_null` | NULL records: almost never legitimate |
| 18 | `is_cname` | CNAME query — used for tunnel downstream data |
| 19 | `is_any` | ANY query — reconnaissance or tunnelling |
| 20 | `is_high_capacity_type` | TXT / NULL / CNAME / ANY / NAPTR |
| 21 | `tld_risk` | Offline abuse-rate score for the TLD |
| 22 | `tld_length` | Length of the top-level domain |
| 23 | `is_numeric_tld` | Binary: TLD is all digits (malformed) |
| 24 | `numeric_label_count` | Labels that are entirely digits |
| 25 | `payload_size` | Wire size of the request packet |
| 26 | `is_tcp` | Binary: arrived over TCP (large payload or zone transfer) |
| 27 | `bytes_per_label` | Name length divided by label count |

---

## Temporal

*31 features*

**Stateful.** Two rolling windows are maintained — one per source IP, one per
(source IP, registrable zone) pair — both bounded and LRU-evicted so an attacker
cannot exhaust memory by rotating source addresses.

These are the features no single packet can produce, and they are what catch
beaconing and sustained exfiltration.

| # | Feature | Meaning |
|---:|---|---|
| 1 | `iat_mean` | Mean inter-arrival time for this host/zone pair |
| 2 | `iat_std` | Standard deviation of inter-arrival times |
| 3 | `iat_min` | Shortest observed gap |
| 4 | `iat_max` | Longest observed gap |
| 5 | `iat_median` | Median gap — robust to one stalled request |
| 6 | `iat_cv` | sigma/mu of inter-arrival times; ~0 means metronome |
| 7 | `iat_range` | max - min gap |
| 8 | `iat_iqr` | Interquartile range of gaps |
| 9 | `iat_last` | Gap since the previous query to this zone |
| 10 | `beacon_strength` | Autocorrelation-based periodicity score 0..1 |
| 11 | `beacon_period_s` | Estimated beacon interval in seconds |
| 12 | `burstiness` | Goh-Barabasi B; -1 periodic, 0 Poisson, +1 human |
| 13 | `fano_factor` | Variance/mean of binned counts; 1.0 = Poisson |
| 14 | `time_entropy` | Entropy of the arrival-time histogram; low means clustered |
| 15 | `zone_query_count` | Queries seen for this host/zone pair |
| 16 | `zone_unique_subs` | Distinct subdomains seen under one zone |
| 17 | `zone_sub_novelty` | Unique/total — 1.0 means every query is brand new |
| 18 | `zone_is_new_sub` | Binary: this subdomain has not been seen before |
| 19 | `zone_qps` | Queries per second to this zone |
| 20 | `zone_uploaded_bytes` | Cumulative subdomain bytes sent to this zone |
| 21 | `zone_upload_rate` | Bytes of subdomain pushed per second = exfil bandwidth |
| 22 | `zone_qtype_diversity` | Distinct record types used against this zone |
| 23 | `host_query_count` | Total queries from this source IP |
| 24 | `host_unique_zones` | Zone fan-out per host |
| 25 | `host_qps` | Lifetime query rate for this host |
| 26 | `host_qps_10s` | Query rate over the last 10 seconds |
| 27 | `host_qps_60s` | Query rate over the last 60 seconds |
| 28 | `host_nxdomain_60s` | NXDOMAIN storm counter — the classic DGA tell |
| 29 | `zone_age_s` | Seconds since this host first touched this zone |
| 30 | `zone_duty_cycle` | Fraction of the window occupied by queries |
| 31 | `zone_bytes_per_query` | Mean subdomain bytes per query to this zone |

---

## Working with the vector

```python
from chronodns.features import FeatureExtractor, FEATURE_NAMES
from chronodns.types import DNSQuery

fx = FeatureExtractor()                     # one instance per process — it is stateful
feats, vec = fx.extract_vector(DNSQuery(qname='a.b.example.com', qtype='TXT'))

feats['shannon_entropy_sub']                # dict access by name
vec.shape                                   # (104,) float32, frozen order
dict(zip(FEATURE_NAMES, vec))               # the two views are equivalent
```

Batch a whole capture (temporal state is rebuilt from scratch, so results are reproducible):

```python
matrix, rows = fx.batch(queries)            # (n, 104) float32
```
