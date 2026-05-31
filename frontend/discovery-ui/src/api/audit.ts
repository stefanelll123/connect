import { apiClient } from "./client";

export interface AuditEvent {
  event_id: string;
  ts: string;
  actor_type: string;
  actor_id: string | null;
  action: string;
  target_type?: string;
  target_id?: string;
  summary?: string | Record<string, unknown>;
  request_id?: string;
  event_hash?: string;
}

export interface AuditListResponse {
  items: AuditEvent[];
  count: number;
  next_cursor?: string;
}

export interface VerifyIntegrityRequest {
  from_dt?: string;
  to_dt?: string;
}

export interface TamperCheckResult {
  events_checked: number;
  tampered_count: number;
  first_tampered_event_id: string | null;
}

export async function listAuditEvents(params?: {
  actor_id?: string;
  action?: string;
  target_type?: string;
  from?: string;
  to?: string;
  cursor?: string;
  limit?: number;
}): Promise<AuditListResponse> {
  const { data } = await apiClient.get<AuditListResponse>("/audit/events", { params });
  return data;
}

export async function getTamperCheckStatus(
  params?: VerifyIntegrityRequest,
): Promise<TamperCheckResult> {
  const { data } = await apiClient.post<TamperCheckResult>("/audit/verify-integrity", params ?? {});
  return data;
}

/** Stream audit events as JSONL and trigger browser download */
export async function exportAuditEventsJSONL(
  params: Record<string, string | number | undefined>,
  onProgress: (n: number) => void,
): Promise<void> {
  const url = new URL(
    `${import.meta.env.VITE_API_BASE_URL ?? ""}/api/v1/audit/events`,
    window.location.origin,
  );
  url.searchParams.set("format", "jsonl");
  url.searchParams.set("stream", "true");
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") url.searchParams.set(k, String(v));
  }

  const response = await fetch(url.toString(), {
    headers: { Accept: "application/x-ndjson" },
  });
  if (!response.ok) throw new Error(`Export failed: ${response.status}`);
  if (!response.body) throw new Error("No response body");

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let eventCount = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    // Count newlines as rough event count
    eventCount += Array.from(value).filter((b) => b === 10).length;
    onProgress(eventCount);
  }

  const blob = new Blob(chunks as unknown as BlobPart[], { type: "application/x-ndjson" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `audit-export-${new Date().toISOString().slice(0, 10)}.jsonl`;
  link.click();
  URL.revokeObjectURL(link.href);
}
