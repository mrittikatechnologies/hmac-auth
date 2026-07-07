// # Hono middleware for Cloudflare Workers
// src/middleware/hono-worker.ts

import type { Context, Next, MiddlewareHandler } from 'hono';
import { verifyHmacRequest } from '../verify';
import { CloudflareKVStore } from '../adapters/cloudflare-kv';
import { KVNamespace } from '@cloudflare/workers-types';

export interface WorkerBindings {
  HMAC_SECRET: string;
  NONCE_STORE: KVNamespace;
}

export function hmacAuthWorker
  <B extends WorkerBindings,
    V extends { Variables: { bodyText: string } }
  >(): MiddlewareHandler<{ Bindings: B; Variables: V['Variables'] }> {
  return async (c: Context, next: Next) => {
    const method = c.req.method;
    const path = new URL(c.req.url).pathname;
    const bodyText = method === 'GET' ? '' : await c.req.text();
    c.set('bodyText' as never, bodyText);

    const result = await verifyHmacRequest({
      secret: c.env.HMAC_SECRET,
      nonceStore: new CloudflareKVStore(c.env.NONCE_STORE),
      signature: c.req.header('X-Signature') ?? '',
      timestamp: c.req.header('X-Timestamp') ?? '',
      nonce: c.req.header('X-Nonce') ?? '',
      method,
      path,
      body: bodyText,
    });

    if (!result.valid) {
      return c.json({ error: 'Unauthorized', reason: result.reason }, 401);
    }

    await next();
  };
}