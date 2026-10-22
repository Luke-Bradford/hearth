"""Small text checks shared by the scanners and the naming rules (no Hearth imports)."""
import re


def looks_like_id(name):
    """Random-looking identifiers (hex ids, UUIDs) make poor display names."""
    return bool(re.fullmatch(r"[0-9a-fA-F-]{12,}", name or ""))
