import { apiClient } from "./client";

export interface StatusList {
  status_list_id: string;
  issuer_did: string;
  env: string;
  credential_type: string | null;
  top_index: number;
  max_size: number;
  is_frozen: boolean;
  dirty: boolean;
  published_at: string | null;
  version: number;
}

export interface StatusListListResponse {
  items: StatusList[];
  total: number;
}

export interface ListStatusListsParams {
  env?: string;
  credential_type?: string;
  skip?: number;
  limit?: number;
}

export async function listStatusLists(
  params: ListStatusListsParams = {},
): Promise<StatusListListResponse> {
  const { data } = await apiClient.get<StatusListListResponse>("/status-lists", { params });
  return data;
}
