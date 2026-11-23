"""Pure-Python vector math (numpy is ABSENT in the venv -- C4 baseline)."""
from __future__ import annotations

import math
from operator import mul


def dot(a, b):
    return sum(map(mul, a, b))


def norm(a) -> float:
    return math.sqrt(sum(x * x for x in a))


def normalize(v):
    """Unit vector, or None for a zero-norm vector."""
    n = norm(v)
    if n == 0.0 or not math.isfinite(n):
        return None
    return [x / n for x in v]


def cosine(a, b) -> float:
    """Cosine similarity; 0.0 for zero-norm inputs (never raises)."""
    na, nb = norm(a), norm(b)
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot(a, b) / (na * nb)
