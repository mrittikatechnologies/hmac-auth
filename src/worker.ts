// packages/hmac-auth/src/worker.ts

import type { Context, Next, MiddlewareHandler } from 'hono';
import {
  computeHmac,
  buildPayload,
  timingSafeEqual,
  isTimestampFresh,
  NONCE_REGEX,
  REPLAY_WINDOW_SEC,
} from './core';

import type { KVNamespace } from '@cloudflare/workers-types';

// KV binding shape — your Worker's Bindings type must include these
export interface HmacBindings {
  HMAC_SECRET: string;
  NONCE_STORE: KVNamespace;
}

export interface HmacOptions {
  // Optional: override which secret to use (useful for rotation)
  secretKey?: string;
  // Optional: custom rejection handler
  onReject?: (c: Context, reason: string) => Response;
}

export function hmacAuth<B extends HmacBindings, V extends { Variables: { bodyText: string } }>(
  options: HmacOptions = {}
): MiddlewareHandler<{ Bindings: B; Variables: V['Variables'] }> {
  return async (c: Context, next: Next) => {
    const reject = options.onReject
      ?? ((ctx: Context, reason: string) =>
        ctx.json({ error: 'Unauthorized', reason }, 401));

    const signature = c.req.header('X-Signature');
    const timestamp = c.req.header('X-Timestamp');
    const nonce = c.req.header('X-Nonce');

    // 1. Presence check
    if (!signature || !timestamp || !nonce) {
      return reject(c, 'missing_headers');
    }

    // 2. Nonce format guard — stops KV pollution before anything else
    if (!NONCE_REGEX.test(nonce)) {
      return reject(c, 'malformed_nonce');
    }

    // 3. Timestamp freshness — cheap check, no I/O
    if (!isTimestampFresh(timestamp)) {
      return reject(c, 'stale_timestamp');
    }

    // 4. Signature verification — I/O-free, rules out bad actors before KV
    const method = c.req.method;
    const path = new URL(c.req.url).pathname;
    const bodyText = method === 'GET' ? '' : await c.req.text();

    // Cache body in context so downstream handlers can read it
    c.set('bodyText' as never, bodyText);

    const payload = buildPayload(timestamp, nonce, method, path, bodyText);
    const secret = options.secretKey ?? c.env.HMAC_SECRET;
    const expected = await computeHmac(secret, payload);

    if (!timingSafeEqual(signature, expected)) {
      return reject(c, 'invalid_signature');
    }

    // 5. Replay check — only reaches KV if signature is valid
    const nonceKey = `nonce:${nonce}`;
    const seen = await c.env.NONCE_STORE.get(nonceKey);

    if (seen) {
      return reject(c, 'replay_detected');
    }

    // 6. Mark nonce as consumed — auto-expires with TTL
    await c.env.NONCE_STORE.put(nonceKey, '1', {
      expirationTtl: REPLAY_WINDOW_SEC,
    });

    await next();
  };
}