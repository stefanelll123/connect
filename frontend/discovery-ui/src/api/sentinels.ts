import { apiClient } from "./client";

export interface Sentinel {
  id: string;
  did: string;
  role: "producer" | "consumer";
  env: "prod" | "test" | "dev";
  is_active: boolean;
  computed_status: string | null;
  last_seen: string | null;
}

export interface SentinelListResponse {
  items: Sentinel[];
  count: number;
}

export interface EnrollmentToken {
  token_id: string;
  service_id: string;
  role: "producer" | "consumer";
  env: string;
  status: "pending" | "approved" | "consumed" | "cancelled";
  expires_at: string;
  created_by: string | null;
  approved_by: string | null;
  approved_at: string | null;
  created_at: string | null;
  token?: string | null;
  note?: string | null;
}

/** @deprecated Use EnrollmentToken */
export type Enrollment = EnrollmentToken;

/** @deprecated Use EnrollmentToken */
export type EnrollmentResponse = EnrollmentToken;

export interface EnrollmentTokenListResponse {
  items: EnrollmentToken[];
  total_count: number;
  next_cursor: string | null;
}

export interface EnrollmentRequest {
  service_id: string;
  env: string;
  role: "producer" | "consumer";
  expires_in_seconds: number;
}

export async function listSentinels(params: {
  env?: string;
  role?: string;
  status?: string;
  service_id?: string;
  cursor?: string;
  limit?: number;
}): Promise<SentinelListResponse> {
  const { data } = await apiClient.get<SentinelListResponse>("/sentinels", { params });
  return data;
}

export async function getSentinel(sentinelId: string): Promise<Sentinel> {
  const { data } = await apiClient.get<Sentinel>(`/sentinels/${sentinelId}`);
  return data;
}

export async function createEnrollment(payload: EnrollmentRequest): Promise<EnrollmentToken> {
  const { data } = await apiClient.post<EnrollmentToken>("/sentinels/enrollments", payload);
  return data;
}

export async function listPendingEnrollments(): Promise<EnrollmentToken[]> {
  const { data } = await apiClient.get<EnrollmentTokenListResponse>("/sentinels/enrollments", {
    params: { status: "pending" },
  });
  return data.items;
}

export async function approveEnrollment(tokenId: string): Promise<void> {
  await apiClient.post(`/sentinels/enrollments/${tokenId}/approve`);
}

export async function cancelEnrollment(tokenId: string): Promise<void> {
  await apiClient.post(`/sentinels/enrollments/${tokenId}/cancel`);
}

/** @deprecated Use cancelEnrollment */
export const rejectEnrollment = cancelEnrollment;
