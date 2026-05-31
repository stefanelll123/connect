import { apiClient } from "./client";

export interface Credential {
  credential_id: string;
  jti: string;
  credential_type: string;
  subject_did: string;
  issuer_did: string;
  env: string;
  expires_at: string;
  revoked_at?: string | null;
  status: "active" | "revoked" | "expired";
  status_list_id?: string | null;
  status_list_index?: number | null;
  jwt_vc: string;
}

export interface CredentialListResponse {
  items: Credential[];
  total: number;
}

export interface IssueSentinelIdentityRequest {
  sentinel_id: string;
}

export interface IssueAccessGrantRequest {
  consumer_sentinel_id: string;
  producer_service_id: string;
  env: string;
  scope: string[];
  expires_in_days?: number;
}

export interface IssueServiceBindingRequest {
  sentinel_id: string;
  service_id: string;
}

export interface RevokeCredentialRequest {
  reason: string;
  severity: "low" | "medium" | "critical";
  revoked_by: string;
}

export async function issueSentinelIdentity(payload: IssueSentinelIdentityRequest): Promise<Credential> {
  const { data } = await apiClient.post<Credential>("/credentials/sentinel-identity", payload);
  return data;
}

export async function issueAccessGrant(payload: IssueAccessGrantRequest): Promise<Credential> {
  const { data } = await apiClient.post<Credential>("/credentials/access-grant", payload);
  return data;
}

export async function issueServiceBinding(payload: IssueServiceBindingRequest): Promise<Credential> {
  const { data } = await apiClient.post<Credential>("/credentials/service-binding", payload);
  return data;
}

export async function revokeCredential(
  credentialId: string,
  payload: RevokeCredentialRequest,
): Promise<void> {
  await apiClient.post(`/credentials/${credentialId}/revoke`, payload);
}

export interface ListCredentialsParams {
  env?: string;
  status?: string;
  credential_type?: string;
  skip?: number;
  limit?: number;
}

export async function listCredentials(params: ListCredentialsParams = {}): Promise<CredentialListResponse> {
  const { data } = await apiClient.get<CredentialListResponse>("/credentials", { params });
  return data;
}
