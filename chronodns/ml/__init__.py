"""Machine-learning subpackage: ensemble, heuristics, training."""

from .detectors import CLASSES, EnsembleScores, ThreatEnsemble
from .heuristics import RULES_DOC, classify_by_rules, heuristic_score
from .train import chronological_split, evaluate_model, train_model

__all__ = [
    "ThreatEnsemble", "EnsembleScores", "CLASSES",
    "heuristic_score", "classify_by_rules", "RULES_DOC",
    "train_model", "evaluate_model", "chronological_split",
]
