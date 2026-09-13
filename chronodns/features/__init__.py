"""Feature-engineering subpackage."""

from .extractor import (
    FEATURE_COUNT,
    FEATURE_GROUPS,
    FEATURE_NAMES,
    FeatureExtractor,
    iter_feature_docs,
)
from .lexical import lexical_features, shannon_entropy
from .structural import QTYPE_RISK, TLD_RISK, structural_features
from .temporal import TemporalTracker, burstiness, periodicity_score

__all__ = [
    "FeatureExtractor", "FEATURE_NAMES", "FEATURE_COUNT", "FEATURE_GROUPS",
    "iter_feature_docs", "lexical_features", "shannon_entropy",
    "structural_features", "QTYPE_RISK", "TLD_RISK",
    "TemporalTracker", "burstiness", "periodicity_score",
]
