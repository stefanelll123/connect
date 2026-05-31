import { apiClient } from "./client";

export interface Service {
  id: string;
  app_id: string;
  service_id: string;
  env: "prod" | "test" | "dev";
  display_name: string;
  owner_did: string | null;
  is_active: boolean;
  description: string | null;
  created_at: string | null;
  updated_at: string | null;
  base_url?: string | null;
  chain_sync_pending?: boolean;
  chain_tx_hash?: string | null;
  chain_sync_attempts?: number;
  // optional fields returned by some endpoints
  status?: "active" | "degraded" | "offline";
  last_descriptor_update?: string;
}

export interface ServiceListResponse {
  items: Service[];
  total_count: number;
  next_cursor: string | null;
}

export interface CreateServiceRequest {
  app_id: string;
  service_id: string;
  env: string;
  display_name: string;
  owner_did?: string;
  description?: string;
  base_url?: string;
}

export async function listServices(params: {
  env?: string;
  status?: string;
  page?: number;
  page_size?: number;
}): Promise<ServiceListResponse> {
  const { data } = await apiClient.get<ServiceListResponse>("/services", { params });
  return data;
}

export async function createService(payload: CreateServiceRequest): Promise<Service> {
  const { data } = await apiClient.post<Service>("/services", payload);
  return data;
}

export async function updateService(
  serviceId: string,
  payload: Partial<CreateServiceRequest>,
): Promise<Service> {
  const { data } = await apiClient.patch<Service>(`/services/${serviceId}`, payload);
  return data;
}

export interface EndpointEntry {
  url: string;
  protocol: "http" | "https" | "grpc" | "mqtt";
  weight: number;
  instance_id: string | null;
}

export interface ServiceDescriptor {
  id: string;
  service_id: string;
  env: string;
  producer_sentinel_did: string | null;
  producer_service_did: string | null;
  descriptor_hash: string | null;
  valid_from: string | null;
  valid_until: string | null;
  issued_at: string | null;
  published_at: string | null;
  is_active: boolean;
  endpoints: EndpointEntry[];
}

export async function getServiceDescriptor(
  serviceId: string,
  env: string,
): Promise<ServiceDescriptor> {
  const { data } = await apiClient.get<ServiceDescriptor>(
    `/services/${serviceId}/descriptor`,
    { params: { env } },
  );
  return data;
}
