/** Small data-loading and routing hooks. No external state library needed. */

import { useCallback, useEffect, useRef, useState } from 'react';

import { ApiError } from './api/client.ts';

export interface AsyncState<T> {
  data?: T;
  error?: { message: string; problems?: string[] };
  loading: boolean;
  reload: () => void;
}

/**
 * Load data on mount and whenever `deps` change.
 * Tracks a generation counter so a slow earlier request cannot overwrite a
 * newer result.
 */
export function useAsync<T>(loader: () => Promise<T>, deps: readonly unknown[] = []): AsyncState<T> {
  const [data, setData] = useState<T | undefined>();
  const [error, setError] = useState<{ message: string; problems?: string[] } | undefined>();
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const generation = useRef(0);

  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    const current = ++generation.current;
    setLoading(true);
    setError(undefined);

    loader()
      .then((value) => {
        if (generation.current !== current) return;
        setData(value);
      })
      .catch((err: unknown) => {
        if (generation.current !== current) return;
        setError(
          err instanceof ApiError
            ? { message: err.message, problems: err.problems }
            : { message: err instanceof Error ? err.message : 'Unexpected error.' },
        );
      })
      .finally(() => {
        if (generation.current === current) setLoading(false);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  return {
    ...(data !== undefined ? { data } : {}),
    ...(error !== undefined ? { error } : {}),
    loading,
    reload,
  };
}

/** Re-run `fn` on an interval, for the live-events view. */
export function usePolling(fn: () => void, intervalMs: number, enabled: boolean): void {
  useEffect(() => {
    if (!enabled) return;
    const handle = window.setInterval(fn, intervalMs);
    return () => window.clearInterval(handle);
  }, [fn, intervalMs, enabled]);
}

export interface Route {
  page: string;
  param?: string;
}

/**
 * Hash routing. Chosen over the History API so the console can be served as
 * static files from S3/CloudFront with no server-side rewrite rules.
 */
export function parseHash(hash: string): Route {
  const cleaned = hash.replace(/^#\/?/, '');
  const [page, param] = cleaned.split('/');
  return {
    page: page !== undefined && page.length > 0 ? page : 'overview',
    ...(param !== undefined && param.length > 0 ? { param: decodeURIComponent(param) } : {}),
  };
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => parseHash(window.location.hash));

  useEffect(() => {
    const onChange = (): void => setRoute(parseHash(window.location.hash));
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);

  return route;
}

export function navigate(page: string, param?: string): void {
  window.location.hash = param === undefined ? `#/${page}` : `#/${page}/${encodeURIComponent(param)}`;
}
