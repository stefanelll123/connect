import { apiClient } from "./client";

export interface App {
  id: string;
  name: string;
  owner: string | null;
  is_active: boolean;
  created_at: string | null;
  updated_at: string | null;
}

export interface AppListResponse {
  items: App[];
  total_count: number;
  next_cursor: string | null;
}

export interface CreateAppRequest {
  name: string;
  owner?: string;
}

export interface UpdateAppRequest {
  name?: string;
  owner?: string;
}

export async function listApps(params: { limit?: number; cursor?: string } = {}): Promise<AppListResponse> {
  const { data } = await apiClient.get<AppListResponse>("/apps", { params });
  return data;
}

export async function createApp(payload: CreateAppRequest): Promise<App> {
  const { data } = await apiClient.post<App>("/apps", payload);
  return data;
}

export async function updateApp(appId: string, payload: UpdateAppRequest): Promise<App> {
  const { data } = await apiClient.patch<App>(`/apps/${appId}`, payload);
  return data;
}

export async function deleteApp(appId: string): Promise<void> {
  await apiClient.delete(`/apps/${appId}`);
}
