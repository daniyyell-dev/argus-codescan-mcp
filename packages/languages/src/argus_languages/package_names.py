"""Small reusable name-similarity check for dependency review heuristics."""

from __future__ import annotations


def looks_like_package(name: str, known: tuple[str, ...]) -> bool:
    """Match one insertion/deletion/substitution/transposition, excluding exact names."""
    name = name.casefold().replace("_", "-")
    for candidate in known:
        candidate = candidate.casefold().replace("_", "-")
        if name == candidate or abs(len(name) - len(candidate)) > 1:
            continue
        if len(name) == len(candidate):
            differences = [
                i for i, (left, right) in enumerate(zip(name, candidate)) if left != right
            ]
            if len(differences) == 1:
                return True
            if len(differences) == 2:
                left, right = differences
                if (
                    right == left + 1
                    and name[left] == candidate[right]
                    and name[right] == candidate[left]
                ):
                    return True
        else:
            short, long = sorted((name, candidate), key=len)
            if any(short == long[:i] + long[i + 1 :] for i in range(len(long))):
                return True
    return False
