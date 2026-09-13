"""
Domain Generation Algorithm simulators.

Six *behavioural families* modelled on publicly documented malware DGA
archetypes. These are re-implementations of the published *shape* of each
family (character distribution, length, TLD choice, seeding strategy) for the
purpose of training a defensive classifier — they contain no malware code and
resolve nowhere: every generated name lands in a reserved or lab TLD unless
you explicitly ask otherwise.

Why six families? Because a detector trained on one algorithm learns that
algorithm, not the concept. Mixing arithmetic, hash-based, dictionary and
permutation DGAs forces the model to learn *linguistic implausibility*, which
is what actually generalises to families it has never seen.
"""

from __future__ import annotations

import hashlib
import random
import string
from dataclasses import dataclass

LAB_TLDS = ["example", "test", "invalid", "localhost.lab"]
REALISTIC_TLDS = ["top", "xyz", "cc", "biz", "info", "click", "monster", "cyou"]

_CONSONANTS = "bcdfghjklmnpqrstvwxyz"
_VOWELS = "aeiou"

# Dictionary-DGA word pool (suppobox / matsnu style: real words concatenated).
_WORDS = ["about", "above", "accept", "across", "action", "after", "again", "against", "alone", "along", "already", "also", "always", "among", "amount", "animal", "answer", "appear", "apple", "area", "around", "arrive", "artist", "aside", "asleep", "attack", "author", "autumn", "avenue", "awake", "award", "aware", "barely", "basket", "battle", "beach", "beauty", "become", "before", "begin", "behind", "believe", "below", "beside", "better", "between", "beyond", "bicycle", "bigger", "binder", "bitter", "blanket", "bottle", "bottom", "branch", "bridge", "bright", "broken", "brother", "bucket", "budget", "builder", "bullet", "burden", "butter", "button", "camera", "cancel", "candle", "canvas", "carbon", "career", "carpet", "carrot", "castle", "casual", "center", "chance", "change", "charge", "cheese", "cherry", "chicken", "choice", "circle", "city", "class", "clean", "clear", "clever", "climate", "close", "cloud", "coffee", "collect", "color", "column", "combine", "comfort", "common", "compare", "complete", "concept", "concern", "connect", "consider", "contact", "contain", "content", "context", "continue", "control", "copper", "corner", "cotton", "could", "country", "couple", "course", "cover", "create", "credit", "crowd", "crystal", "culture", "current", "custom", "damage", "danger", "daughter", "decide", "decline", "degree", "deliver", "demand", "depend", "desert", "design", "desire", "detail", "develop", "device", "differ", "dinner", "direct", "discuss", "display", "distance", "divide", "doctor", "dollar", "double", "dragon", "drama", "dream", "drive", "during", "eager", "early", "earth", "easily", "eastern", "economy", "edition", "effect", "effort", "either", "eleven", "emerge", "empty", "enable", "energy", "engine", "enough", "enter", "entire", "equal", "escape", "estate", "evening", "event", "every", "exact", "example", "except", "exchange", "exist", "expand", "expect", "expert", "explain", "export", "extend", "extra", "fabric", "factor", "family", "famous", "farmer", "fashion", "father", "favor", "feature", "figure", "filter", "final", "finger", "finish", "first", "fiscal", "flight", "flower", "follow", "forest", "forget", "formal", "format", "forward", "frame", "friend", "front", "fruit", "future", "garden", "gather", "gender", "gentle", "gather", "global", "golden", "govern", "grade", "grand", "grant", "graph", "great", "green", "ground", "group", "growth", "guard", "guess", "guest", "guide", "habit", "handle", "happen", "harbor", "health", "heart", "heavy", "height", "hidden", "history", "holder", "honest", "horizon", "hotel", "human", "hundred", "hunger", "husband", "ignore", "image", "impact", "import", "income", "indeed", "index", "indoor", "inform", "inner", "insect", "inside", "instead", "intend", "invite", "island", "itself", "jacket", "journal", "junior", "justice", "kitchen", "knowledge", "ladder", "language", "larger", "latter", "launch", "layer", "leader", "league", "learn", "least", "leave", "legal", "length", "lesson", "letter", "level", "light", "likely", "limit", "linear", "liquid", "listen", "little", "living", "local", "locate", "London", "longer", "lucky", "luggage", "machine", "magnet", "major", "making", "manage", "manner", "marble", "margin", "market", "master", "matter", "meadow", "measure", "medical", "medium", "member", "memory", "mental", "merchant", "metal", "method", "middle", "might", "mineral", "minute", "mirror", "mobile", "modern", "moment", "monitor", "month", "morning", "mother", "motion", "mountain", "moving", "murder", "muscle", "museum", "music", "narrow", "nation", "native", "nature", "nearly", "needle", "neither", "nervous", "network", "neutral", "never", "notice", "number", "object", "observe", "obtain", "occupy", "ocean", "offer", "office", "often", "oldest", "only", "option", "orange", "order", "origin", "other", "outer", "output", "outside", "oxygen", "packet", "palace", "panel", "paper", "parent", "parking", "partner", "passage", "patient", "pattern", "payment", "people", "period", "person", "phrase", "picture", "piece", "pilot", "place", "plain", "planet", "plant", "plastic", "plate", "please", "pocket", "point", "policy", "polish", "popular", "portion", "position", "possible", "potato", "powder", "power", "practice", "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "prince", "print", "prison", "private", "problem", "process", "produce", "profile", "profit", "program", "project", "proper", "propose", "protect", "proud", "provide", "public", "purple", "purpose", "quality", "quarter", "question", "quickly", "quiet", "radio", "raise", "random", "range", "rapid", "rather", "reach", "ready", "reason", "receive", "recent", "record", "reduce", "reflect", "regard", "region", "regular", "reject", "relate", "release", "remain", "remember", "remove", "repair", "repeat", "replace", "report", "request", "require", "rescue", "research", "reserve", "resist", "resource", "respect", "respond", "result", "retain", "return", "reveal", "review", "reward", "rhythm", "ribbon", "right", "rising", "river", "rocket", "roller", "rotate", "round", "royal", "rubber", "rural", "sacred", "saddle", "safety", "salad", "sample", "satisfy", "scale", "scene", "school", "science", "score", "screen", "search", "season", "second", "secret", "section", "sector", "secure", "select", "senior", "sense", "sentence", "series", "serious", "servant", "service", "settle", "seven", "several", "shadow", "shall", "shape", "share", "sharp", "shelter", "shift", "shine", "ship", "shock", "short", "should", "shoulder", "shower", "signal", "silent", "silver", "similar", "simple", "single", "sister", "situation", "sketch", "skill", "slight", "small", "smart", "smile", "smoke", "smooth", "social", "society", "soften", "solid", "solve", "someone", "sorry", "sound", "source", "south", "space", "speak", "special", "speed", "spend", "spirit", "spoken", "spread", "spring", "square", "stable", "staff", "stage", "stand", "start", "state", "station", "status", "steady", "steel", "stone", "store", "storm", "story", "straight", "strange", "stream", "street", "stress", "strike", "strong", "struggle", "student", "studio", "study", "stupid", "style", "subject", "submit", "succeed", "sudden", "suffer", "sugar", "suggest", "summer", "sunset", "supply", "support", "suppose", "surface", "surprise", "survey", "survive", "sweet", "switch", "symbol", "system", "table", "tablet", "talent", "target", "teacher", "telephone", "tender", "tennis", "terrible", "thank", "theory", "therefore", "thick", "thing", "think", "third", "thought", "threat", "three", "throat", "through", "thrown", "ticket", "tiger", "tight", "timber", "title", "today", "together", "tomorrow", "tongue", "tonight", "topic", "total", "touch", "toward", "towel", "tower", "trade", "traffic", "train", "transfer", "travel", "treat", "trend", "trial", "tribe", "trouble", "truck", "truly", "trust", "truth", "turkey", "turning", "twelve", "twenty", "twice", "typical", "umbrella", "uncle", "under", "unique", "united", "unless", "unlike", "until", "update", "upper", "urban", "usual", "valley", "value", "vapor", "various", "vehicle", "velvet", "vendor", "venture", "verbal", "version", "vessel", "victim", "victory", "video", "village", "violet", "virtual", "vision", "visit", "visual", "vital", "voice", "volume", "voyage", "waiting", "walking", "wander", "warning", "washing", "watching", "water", "wealth", "weapon", "weather", "wedding", "weekly", "weight", "welcome", "welfare", "western", "whether", "which", "while", "whisper", "white", "whole", "widely", "willing", "window", "winter", "wisdom", "within", "without", "wonder", "wooden", "worker", "working", "world", "worry", "worth", "would", "wrong", "yellow", "yesterday", "yield", "young", "yourself"]


@dataclass
class DGAFamily:
    name: str
    description: str
    tlds: list[str]
    min_len: int
    max_len: int


FAMILIES: dict[str, DGAFamily] = {
    "arithmetic": DGAFamily(
        "arithmetic", "LCG over the alphabet — Conficker/Kraken archetype",
        ["example", "test", "top"], 8, 14),
    "hashbased": DGAFamily(
        "hashbased", "MD5/SHA of a date seed, hex-truncated — CryptoLocker archetype",
        ["example", "invalid", "xyz"], 12, 22),
    "wordlist": DGAFamily(
        "wordlist", "Two dictionary words concatenated — Suppobox/Matsnu archetype",
        ["example", "test", "cc"], 10, 20),
    "permutation": DGAFamily(
        "permutation", "Character permutation of a seed domain — Banjori archetype",
        ["example", "biz"], 10, 18),
    "markov": DGAFamily(
        "markov", "Pronounceable CVCV syllables — Necurs/Gozi archetype",
        ["example", "test", "info"], 9, 16),
    "base36": DGAFamily(
        "base36", "Timestamp encoded in base36 — Ramnit/Tinba archetype",
        ["example", "invalid", "monster"], 10, 18),
}


class DGAGenerator:
    """Deterministic, seedable generator for all six families."""

    def __init__(self, seed: int = 1337, realistic_tlds: bool = False) -> None:
        self.rng = random.Random(seed)
        self.realistic = realistic_tlds

    # -- family implementations --------------------------------------- #
    def _arithmetic(self, n: int) -> str:
        """Linear congruential generator mapped onto a-z0-9."""
        alphabet = string.ascii_lowercase + string.digits
        x = self.rng.randrange(1, 2 ** 31 - 1)
        out = []
        for _ in range(n):
            x = (x * 1103515245 + 12345) & 0x7FFFFFFF
            out.append(alphabet[x % len(alphabet)])
        return "".join(out)

    def _hashbased(self, n: int) -> str:
        seed = f"{self.rng.random()}{self.rng.randrange(1 << 30)}".encode()
        digest = hashlib.md5(seed).hexdigest() + hashlib.sha1(seed).hexdigest()
        return digest[:n]

    def _wordlist(self, n: int) -> str:
        # Deliberately hard: real words defeat naive entropy-only detectors.
        # Only the n-gram + label-length + TLD-risk features catch these.
        w1, w2 = self.rng.sample(_WORDS, 2)
        name = w1 + w2
        if self.rng.random() < 0.3:
            name += str(self.rng.randrange(10, 99))
        return name[: max(n, 10)]

    def _permutation(self, n: int) -> str:
        base = self.rng.choice(["earnest", "mercury", "atlantic", "provider",
                                "software", "database", "terminal", "protocol"])
        chars = list(base)
        for _ in range(self.rng.randrange(2, 5)):
            i, j = self.rng.randrange(len(chars)), self.rng.randrange(len(chars))
            chars[i], chars[j] = chars[j], chars[i]
        extra = "".join(self.rng.choice(string.ascii_lowercase)
                        for _ in range(max(0, n - len(chars))))
        return "".join(chars) + extra

    def _markov(self, n: int) -> str:
        out = []
        while len("".join(out)) < n:
            out.append(self.rng.choice(_CONSONANTS) + self.rng.choice(_VOWELS))
        return "".join(out)[:n]

    def _base36(self, n: int) -> str:
        alphabet = string.digits + string.ascii_lowercase
        value = self.rng.randrange(10 ** 12, 10 ** 18)
        out = []
        while value and len(out) < n:
            value, rem = divmod(value, 36)
            out.append(alphabet[rem])
        while len(out) < n:
            out.append(self.rng.choice(alphabet))
        return "".join(out)

    # -- public API ---------------------------------------------------- #
    def generate(self, family: str | None = None) -> tuple[str, str]:
        """Return (fqdn, family_name)."""
        fam_name = family or self.rng.choice(list(FAMILIES))
        fam = FAMILIES[fam_name]
        n = self.rng.randrange(fam.min_len, fam.max_len + 1)
        label = getattr(self, f"_{fam_name}")(n)
        label = "".join(c for c in label if c.isalnum() or c == "-").lower()[:63] or "x"
        tlds = REALISTIC_TLDS if self.realistic else fam.tlds
        tld = self.rng.choice(tlds)
        return f"{label}.{tld}", fam_name

    def batch(self, count: int, family: str | None = None) -> list[tuple[str, str]]:
        return [self.generate(family) for _ in range(count)]
