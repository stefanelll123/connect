import { useState, useEffect, useCallback } from "react";

interface QueryState<T> {
  data: T | null;
  isLoading: boolean;
  error: unknown;
  refetch: () => void;
}

interface QueryOptions {
  enabled?: boolean;
}

// Minimal typed query hook (no external dependency)
export function useQuery<T>(
  key: unknown[],
  fetcher: () => Promise<T>,
  options: QueryOptions = {},
): QueryState<T> {
  const enabled = options.enabled !== false;
  const keyStr = JSON.stringify(key);
  const [data, setData] = useState<T | null>(null);
  const [isLoading, setIsLoading] = useState(enabled);
  const [error, setError] = useState<unknown>(null);
  const [tick, setTick] = useState(0);

  const refetch = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    if (!enabled) {
      setIsLoading(false);
      return;
    }
    let cancelled = false;
    setData(null);
    setError(null);
    setIsLoading(true);
    fetcher()
      .then((result) => {
        if (!cancelled) {
          setData(result);
          setError(null);
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err);
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick, enabled, keyStr]);

  return { data, isLoading, error, refetch };
}
