import { apiClient } from "./client";

export interface ChainStatus {
  network: string;
  chain_id: number;
  rpc_url: string;
  is_available: boolean;
  indexer_last_block: number;
  blockchain_integration_enabled: boolean;
  policy_cache: {
    is_stale: boolean;
    cache_age_seconds: number | null;
  };
}

export interface ChainEvent {
  id: string;
  tx_hash: string;
  block_number: number;
  event_name: string;
  contract: string;
  args: Record<string, unknown> | null;
  indexed_at: string | null;
}

export interface ChainEventsResponse {
  items: ChainEvent[];
  count: number;
}

export async function getChainStatus(): Promise<ChainStatus> {
  const { data } = await apiClient.get<ChainStatus>("/chain/status");
  return data;
}

export async function listChainEvents(params?: {
  contract?: string;
  event_name?: string;
  from_block?: number;
  since?: string;
  limit?: number;
}): Promise<ChainEventsResponse> {
  const { data } = await apiClient.get<ChainEventsResponse>("/chain/events", { params });
  return data;
}
