"""
Permutation engine module for SubRecon 2026.
"""
import re
from ..config import PERMUTATION_RULES, COMMON_WORDS


def generate_permutations(seed_subdomains):
    """Recursive permutations of found subdomains."""
    permutations = set()
    for sub in seed_subdomains:
        base = sub.split('.')[0]
        for prefix, suffix in PERMUTATION_RULES:
            permutations.add(prefix + base)
            permutations.add(base + suffix)
        # number substitution
        permutations.add(re.sub(r'\d+', '01', base))
        # hyphen variations
        permutations.add(base.replace('-', ''))
        permutations.add(base.replace('-', '_'))
    return permutations