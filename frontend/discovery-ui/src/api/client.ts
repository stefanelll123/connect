import axios, { AxiosError } from "axios";
import { User } from "oidc-client-ts";

// Typed error surface for API calls
export interface ApiError {
  status: number;
  code: string;
  message: string;
}

// Module-level auth context reference (set by AuthProvider integration)
let _getUser: (() => User | null | undefined) | null = null;
let _signinSilent: (() => Promise<User | null>) | null = null;
let _signinRedirect: (() => Promise<void>) | null = null;

export function registerAuthHandlers(
  getUser: () => User | null | undefined,
  signinSilent: () => Promise<User | null>,
  signinRedirect: () => Promise<void>,
) {
  _getUser = getUser;
  _signinSilent = signinSilent;
  _signinRedirect = signinRedirect;
}

export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000/api/v1",
  timeout: 30_000,
});

// Request interceptor: inject Bearer token
apiClient.interceptors.request.use((config) => {
  const user = _getUser?.();
  if (user?.access_token) {
    config.headers.Authorization = `Bearer ${user.access_token}`;
  }
  return config;
});

// Response interceptor: handle 401 with one silent refresh, then redirect
let _refreshing = false;
apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    if (error.response?.status === 401 && !_refreshing && _signinSilent) {
      _refreshing = true;
      try {
        const refreshed = await _signinSilent();
        if (refreshed?.access_token) {
          error.config!.headers!.Authorization = `Bearer ${refreshed.access_token}`;
          _refreshing = false;
          return apiClient.request(error.config!);
        }
      } catch {
        // silent refresh failed
      }
      _refreshing = false;
      await _signinRedirect?.();
      return Promise.reject(error);
    }

    const apiError: ApiError = {
      status: error.response?.status ?? 0,
      code: (error.response?.data as { code?: string })?.code ?? "NETWORK_ERROR",
      message:
        (error.response?.data as { message?: string })?.message ?? error.message,
    };
    return Promise.reject(apiError);
  },
);
