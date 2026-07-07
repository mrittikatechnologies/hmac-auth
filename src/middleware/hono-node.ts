// src/middleware/hono-node.ts
// # Hono middleware for Node/Bun/Render

import type { Context, Next, MiddlewareHandler } from 'hono';
import { verifyHmacRequest } from '../verify';

// Accepts any NonceStore implementation — inject at setup time
import type { NonceStore } from '../adapters/types';

export interface NodeMiddlewareOptions {
  secret: string;
  nonceStore: NonceStore; // inject Redis, Memory, or any custom store
}

export function hmacAuthNode(
  options: NodeMiddlewareOptions
): MiddlewareHandler {
  return async (c: Context, next: Next) => {
    const method = c.req.method;
    const path = new URL(c.req.url).pathname;
    const bodyText = method === 'GET' ? '' : await c.req.text();
    c.set('bodyText' as never, bodyText);

    const result = await verifyHmacRequest({
      secret: options.secret,
      nonceStore: options.nonceStore,
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