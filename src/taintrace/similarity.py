"""Similarity algorithms for package name comparison."""

import functools
from typing import List, Tuple

from rapidfuzz.distance import Levenshtein

# A four-character Soundex code can describe a name up to roughly this long;
# beyond it the code saturates and collisions stop being meaningful.
SOUNDEX_TRUSTED_LENGTH = 12

_SOUNDEX_MAP = {
    'b': '1', 'f': '1', 'p': '1', 'v': '1',
    'c': '2', 'g': '2', 'j': '2', 'k': '2',
    'q': '2', 's': '2', 'x': '2', 'z': '2',
    'd': '3', 't': '3',
    'l': '4',
    'm': '5', 'n': '5',
    'r': '6',
}


class SimilarityEngine:
    CONFUSABLES = str.maketrans({
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
        "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
        "ɡ": "g", "ɑ": "a", "ε": "e", "ο": "o", "υ": "u",
        "０": "0", "１": "1", "２": "2", "３": "3", "４": "4",
        "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
    })

    """Calculate similarity between package names using multiple algorithms."""

    def similarity(self, name1: str, name2: str) -> float:
        """Combined similarity score (0.0 to 1.0)."""
        if name1 == name2:
            return 1.0

        # Levenshtein-based similarity
        lev_score = self._levenshtein_similarity(name1, name2)

        # Phonetic similarity using Soundex. It reuses `lev_score` when the
        # Soundex codes collide on long names, and the homoglyph pass reuses it
        # for pure-ASCII names -- otherwise the same distance is recomputed up
        # to three times per candidate.
        phonetic_score = self._phonetic_similarity(name1, name2, lev_score=lev_score)

        # Substring and homoglyph matching
        substring_score = self._substring_similarity(name1, name2)
        if name1.isascii() and name2.isascii():
            homoglyph_score = lev_score
        else:
            homoglyph_score = self._homoglyph_similarity(name1, name2)

        # A normalized homoglyph match is a strong signal by itself.
        return max(
            lev_score * 0.5 + phonetic_score * 0.1 + substring_score * 0.1 + homoglyph_score * 0.3,
            lev_score, phonetic_score, substring_score, homoglyph_score,
        )

    def levenshtein(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings.

        Backed by rapidfuzz (a declared dependency): the same metric as the
        textbook dynamic-programming matrix, ~40x faster, which matters now that
        the java ecosystem carries thousands of coordinates to compare against.
        """
        return Levenshtein.distance(s1, s2)

    def _levenshtein_similarity(self, s1: str, s2: str) -> float:
        """Normalized Levenshtein similarity (1.0 = identical)."""
        return Levenshtein.normalized_similarity(s1, s2)

    def _phonetic_similarity(self, s1: str, s2: str, lev_score: float | None = None) -> float:
        """Phonetic similarity using Soundex.

        Soundex emits a fixed four-character code, so it saturates on long names:
        every ``org.*`` Maven coordinate hashes to ``o621``. A bare code equality
        is therefore only trustworthy when the names are short enough for the
        code to describe them. When the codes collide on longer names, the score
        is damped by the Levenshtein similarity of the full strings, so an
        unrelated package is not promoted to a perfect phonetic match (#77).
        """
        sx1 = self._soundex(s1)
        sx2 = self._soundex(s2)
        longest = max(len(s1), len(s2))
        saturated = longest > SOUNDEX_TRUSTED_LENGTH
        if sx1 == sx2:
            if not saturated:
                return 1.0
            return lev_score if lev_score is not None else self._levenshtein_similarity(s1, s2)
        # Partial match
        matches = sum(1 for a, b in zip(sx1, sx2) if a == b)
        return matches / max(len(sx1), len(sx2))

    @staticmethod
    @functools.lru_cache(maxsize=8192)
    def _soundex(s: str) -> str:
        """Simple Soundex implementation.

        Memoized: comparing a query against a known-package set recomputes the
        code for every candidate on every call, which dominated the runtime once
        the java ecosystem carried thousands of coordinates.
        """
        if not s:
            return ""
        s = s.lower()
        soundex_map = _SOUNDEX_MAP
        result = [s[0]]
        prev_code = ''
        for char in s[1:]:
            code = soundex_map.get(char, '')
            if code and code != prev_code:
                result.append(code)
                prev_code = code
            if len(result) == 4:
                break
        return ''.join(result).ljust(4, '0')

    @staticmethod
    @functools.lru_cache(maxsize=8192)
    def normalize_homoglyphs(s: str) -> str:
        """Normalize a small, high-confidence set of Unicode confusables.

        Memoized for the same reason as `_soundex`: it is recomputed for every
        candidate on every similarity query.
        """
        return s.lower().translate(SimilarityEngine.CONFUSABLES)

    _normalize_homoglyphs = normalize_homoglyphs

    def _homoglyph_similarity(self, s1: str, s2: str) -> float:
        """Compare names after normalizing visually confusable characters."""
        # Pure-ASCII names are unaffected by the confusable table, so the second
        # Levenshtein pass would return exactly `lev_score`. Skip it.
        if s1.isascii() and s2.isascii():
            return self._levenshtein_similarity(s1, s2)
        return self._levenshtein_similarity(
            self.normalize_homoglyphs(s1), self.normalize_homoglyphs(s2)
        )

    def _substring_similarity(self, s1: str, s2: str) -> float:
        """Check if one string contains the other."""
        s1_lower = s1.lower()
        s2_lower = s2.lower()
        if s1_lower in s2_lower or s2_lower in s1_lower:
            shorter = min(len(s1), len(s2))
            longer = max(len(s1), len(s2))
            return shorter / longer if longer > 0 else 1.0
        return 0.0

    def could_match(self, name1: str, name2: str, threshold: float) -> bool:
        """Cheap necessary condition for `similarity(name1, name2) >= threshold`.

        `similarity()` is the maximum of its four component scores (the weighted
        blend is a convex combination of them, so it can never exceed their
        maximum), and three of those components -- Levenshtein, substring and
        homoglyph -- all collapse once the two names differ in length by more
        than `(1 - threshold)` of the longer one. The phonetic component is the
        exception: a Soundex code collision scores 1.0 regardless of length, so
        candidates are also kept when their codes are close.

        The result is therefore a *superset* of the real matches: it only skips
        candidates that provably cannot reach the threshold.
        """
        length1, length2 = len(name1), len(name2)
        longer = max(length1, length2)
        if longer and abs(length1 - length2) <= (1.0 - threshold) * longer:
            return True
        code1, code2 = self._soundex(name1), self._soundex(name2)
        if not code1 or not code2:
            return False
        if code1 == code2:
            return True
        matches = sum(1 for a, b in zip(code1, code2) if a == b)
        return matches / max(len(code1), len(code2)) >= threshold
