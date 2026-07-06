// packages/hmac-auth/src/client.ts

import {
  generateNonce,
  computeHmac,
  buildPayload,
  buildAuthHeaders,
} from './core';

export interface WorkerClientConfig {
  workerUrl: string;
  secret: string;
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: Record<string, unknown>;
  headers?: Record<string, string>;
}

export interface WorkerResponse<T> {
  ok: boolean;
  data: T | null;
  error: string | null;
  status: number;
}

// Factory — create one client per Worker endpoint, reuse across requests
export function createWorkerClient(config: WorkerClientConfig) {
  const { workerUrl, secret } = config;

  async function call<T = unknown>(
    path: string,
    options: RequestOptions = {}
  ): Promise<WorkerResponse<T>> {
    const { method = 'GET', body, headers = {} } = options;

    const timestamp = Date.now().toString();
    const nonce = generateNonce();
    const bodyText = body ? JSON.stringify(body) : '';
    const payload = buildPayload(timestamp, nonce, method, path, bodyText);
    const signature = await computeHmac(secret, payload);

    try {
      const res = await fetch(`${workerUrl}${path}`, {
        method,
        headers: {
          'Content-Type': 'application/json',
          ...buildAuthHeaders(signature, timestamp, nonce),
          ...headers,
        },
        body: bodyText || undefined,
      });

      if (!res.ok) {
        return {
          ok: false,
          data: null,
          error: `Worker responded with ${res.status}`,
          status: res.status,
        };
      }

      const data = (await res.json()) as T;
      return { ok: true, data, error: null, status: res.status };

    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown fetch error';
      return { ok: false, data: null, error: message, status: 500 };
    }
  }

  return { call };
}
