"""
Chrono-DNS — ML-Driven DNS Security Gateway & Threat Intelligence Engine.

A defensive, inline DNS resolver that detects DNS tunnelling, DGA (Domain
Generation Algorithm) beacons and C2 exfiltration channels in real time by
combining information-theoretic feature extraction, a supervised +
unsupervised ML ensemble, and a SQL-backed threat-intelligence engine.
"""

__version__ = "1.0.0"
__author__ = "i5 Designs"
__license__ = "MIT"

BANNER = rf"""
   ______ __                             ____  _   _ _____
  / ____// /_   _____ ____   ____   ____ / __ \/ | / // ___/
 / /    / __ \ / ___// __ \ / __ \ / __ \/ / / /  |/ / \__ \
/ /___ / / / // /   / /_/ // / / // /_/ / /_/ / /|  / ___/ /
\____//_/ /_//_/    \____//_/ /_/ \____/_____/_/ |_/ /____/
        ML-Driven DNS Security Gateway  ·  v{__version__}
"""

__all__ = ["__version__", "__author__", "__license__", "BANNER"]
