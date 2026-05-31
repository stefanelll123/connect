"""VC/VP Engine — public API (TASK-041)."""
from common.vc_engine.errors import VCError, VCErrorCode, VPError, VPErrorCode
from common.vc_engine.resolver import DIDDocument, DIDResolver, VerificationMethod
from common.vc_engine.verifier import VerifiedCredential, VerifiedPresentation, verify_vc, verify_vp
from common.vc_engine.builder import create_vp

__all__ = [
    "verify_vc",
    "verify_vp",
    "create_vp",
    "DIDResolver",
    "DIDDocument",
    "VerificationMethod",
    "VerifiedCredential",
    "VerifiedPresentation",
    "VCError",
    "VPError",
    "VCErrorCode",
    "VPErrorCode",
]
