import { WebStorageStateStore } from "oidc-client-ts";

export const oidcConfig = {
  authority: import.meta.env.VITE_OIDC_AUTHORITY ?? "http://localhost:8001/realms/discovery",
  client_id: import.meta.env.VITE_OIDC_CLIENT_ID ?? "discovery-ui",
  redirect_uri: `${window.location.origin}/auth/callback`,
  post_logout_redirect_uri: window.location.origin,
  scope: "openid profile email",
  response_type: "code",
  automaticSilentRenew: true,
  // Store access token in memory (not localStorage)
  userStore: new WebStorageStateStore({ store: window.sessionStorage }),
};
