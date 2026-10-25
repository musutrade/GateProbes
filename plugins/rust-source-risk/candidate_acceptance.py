#!/usr/bin/env python3
"""Local unpublished candidate acceptance; current-release CI remains separate.

Requires an external SHA-256 pin of the candidate manifest, exact archive/member
hashes, fixed fixture inputs and the same immutable published Core as the release
regression. Never emits a release identity or changes the historical 0.2 pins.
"""
import sys
from core_acceptance import AcceptanceError, main

if __name__ == "__main__":
    try:
        raise SystemExit(main(candidate=True))
    except AcceptanceError as error:
        print(f"CANDIDATE ACCEPTANCE FAILED: {error}", file=sys.stderr)
        raise SystemExit(1)
