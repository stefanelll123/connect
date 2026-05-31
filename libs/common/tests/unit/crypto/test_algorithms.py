"""Unit tests for common.crypto.algorithms.

Verifies that:
* ALLOWED_ALGS contains EdDSA (required) and ES256 (optional).
* PROHIBITED_ALGS contains all banned algorithm names including alg:none variants.
* assert_algorithm_allowed passes for allowed algorithms.
* assert_algorithm_allowed raises ProhibitedAlgorithmError for every
  prohibited name and for unknown/unrecognised algorithms.
* The ALLOWED and PROHIBITED sets are disjoint.
"""

from __future__ import annotations

import pytest

from common.crypto.algorithms import (
    ALLOWED_ALGS,
    OPTIONAL_ALGS,
    PROHIBITED_ALGS,
    REQUIRED_ALGS,
    ProhibitedAlgorithmError,
    assert_algorithm_allowed,
)


class TestAlgorithmSets:
    def test_eddsa_is_required(self) -> None:
        assert "EdDSA" in REQUIRED_ALGS

    def test_es256_is_optional(self) -> None:
        assert "ES256" in OPTIONAL_ALGS

    def test_allowed_is_union_of_required_and_optional(self) -> None:
        assert ALLOWED_ALGS == REQUIRED_ALGS | OPTIONAL_ALGS

    def test_allowed_and_prohibited_are_disjoint(self) -> None:
        overlap = ALLOWED_ALGS & PROHIBITED_ALGS
        assert overlap == frozenset(), f"Overlap detected: {overlap}"

    def test_none_variants_are_prohibited(self) -> None:
        for variant in ("none", "None", "NONE"):
            assert variant in PROHIBITED_ALGS, f"'{variant}' must be prohibited"

    def test_symmetric_algs_are_prohibited(self) -> None:
        for alg in ("HS256", "HS384", "HS512"):
            assert alg in PROHIBITED_ALGS

    def test_rsa_algs_are_prohibited(self) -> None:
        for alg in ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512"):
            assert alg in PROHIBITED_ALGS

    def test_empty_string_is_prohibited(self) -> None:
        assert "" in PROHIBITED_ALGS


class TestAssertAlgorithmAllowed:
    @pytest.mark.parametrize("alg", ["EdDSA", "ES256"])
    def test_returns_alg_for_allowed(self, alg: str) -> None:
        result = assert_algorithm_allowed(alg)
        assert result == alg

    def test_raises_for_none_string(self) -> None:
        with pytest.raises(ProhibitedAlgorithmError) as exc_info:
            assert_algorithm_allowed("none")
        assert "none" in str(exc_info.value).lower()

    def test_raises_for_none_python_value(self) -> None:
        with pytest.raises(ProhibitedAlgorithmError):
            assert_algorithm_allowed(None)  # type: ignore[arg-type]

    def test_raises_for_empty_string(self) -> None:
        with pytest.raises(ProhibitedAlgorithmError):
            assert_algorithm_allowed("")

    @pytest.mark.parametrize("alg", ["HS256", "RS256", "PS256", "NONE", "None"])
    def test_raises_for_prohibited(self, alg: str) -> None:
        with pytest.raises(ProhibitedAlgorithmError) as exc_info:
            assert_algorithm_allowed(alg)
        assert exc_info.value.alg == alg

    def test_raises_for_unknown_algorithm(self) -> None:
        with pytest.raises(ProhibitedAlgorithmError):
            assert_algorithm_allowed("A128KW")

    def test_error_message_contains_allowed_algs(self) -> None:
        with pytest.raises(ProhibitedAlgorithmError) as exc_info:
            assert_algorithm_allowed("RS256")
        msg = str(exc_info.value)
        assert "EdDSA" in msg
        assert "ES256" in msg


class TestProhibitedAlgorithmError:
    def test_is_value_error_subclass(self) -> None:
        err = ProhibitedAlgorithmError("RS256")
        assert isinstance(err, ValueError)

    def test_carries_alg_attribute(self) -> None:
        err = ProhibitedAlgorithmError("HS256")
        assert err.alg == "HS256"
