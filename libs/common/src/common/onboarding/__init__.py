"""Onboarding protocol library for the Sentinel identity platform."""

from common.onboarding.models import (
    ChallengeResponse,
    ContractAddresses,
    OnboardCompleteRequest,
    OnboardInitiateRequest,
    OnboardingBundle,
    OnboardingError,
    TrustAnchors,
)
from common.onboarding.proof import (
    OnboardingProofClaims,
    OnboardingProofError,
    create_onboarding_proof,
    verify_onboarding_proof,
)
from common.onboarding.token import (
    EnrollmentTokenClaims,
    EnrollmentTokenError,
    MigrationTicketClaims,
    create_enrollment_token,
    create_migration_ticket,
    hash_token,
    validate_enrollment_token,
    validate_migration_ticket,
)

__all__ = [
    "ChallengeResponse",
    "ContractAddresses",
    "OnboardCompleteRequest",
    "OnboardInitiateRequest",
    "OnboardingBundle",
    "OnboardingError",
    "TrustAnchors",
    "OnboardingProofClaims",
    "OnboardingProofError",
    "create_onboarding_proof",
    "verify_onboarding_proof",
    "EnrollmentTokenClaims",
    "EnrollmentTokenError",
    "MigrationTicketClaims",
    "create_enrollment_token",
    "create_migration_ticket",
    "hash_token",
    "validate_enrollment_token",
    "validate_migration_ticket",
]
