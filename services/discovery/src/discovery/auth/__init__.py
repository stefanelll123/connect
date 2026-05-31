"""Auth package — OIDC/JWT validation, RBAC, and CurrentUser model."""
from discovery.auth.models import CurrentUser
from discovery.auth.rbac import get_current_user, require_roles

__all__ = ["CurrentUser", "get_current_user", "require_roles"]
