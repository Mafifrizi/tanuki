"""Adversarial Challenge & Integration Unit Tests for Milestone 3 (NHI & Token Exchange)."""

import os
import sys
import unittest

tests_dir = os.path.dirname(__file__)
if tests_dir not in sys.path:
    sys.path.insert(0, tests_dir)

from verify_m3_auditor import (
    TestAdversarialBase64AndJson,
    TestAdversarialJwtSecurityPolicies,
    TestAdversarialRfc8693TokenExchange,
)
from verify_m3_challenger_2 import (
    TestAdversarialBroadSubjectPatterns,
    TestAdversarialWildcardAudience,
    TestCliAdversarialAndFuzzExecution,
    TestFuzzMalformedJwtTokens,
    TestFuzzRfc8693TokenExchange,
    TestRustParityAndCodeIntegrity,
)

__all__ = [
    "TestAdversarialBase64AndJson",
    "TestAdversarialJwtSecurityPolicies",
    "TestAdversarialRfc8693TokenExchange",
    "TestAdversarialBroadSubjectPatterns",
    "TestAdversarialWildcardAudience",
    "TestCliAdversarialAndFuzzExecution",
    "TestFuzzMalformedJwtTokens",
    "TestFuzzRfc8693TokenExchange",
    "TestRustParityAndCodeIntegrity",
]

if __name__ == "__main__":
    unittest.main()
