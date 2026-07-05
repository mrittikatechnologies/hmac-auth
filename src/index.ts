// packages/hmac-auth/src/index.ts

// Core utilities (if any app needs raw access)
export {
  computeHmac,
  buildPayload,
  generateNonce,
  timingSafeEqual,
  isTimestampFresh,
  buildAuthHeaders,
  REPLAY_WINDOW_SEC,
} from './core';

// Client factory for any server-side caller
export { createWorkerClient } from './client';
export type { WorkerClientConfig, RequestOptions, WorkerResponse } from './client';

// Hono middleware for Cloudflare Workers
export { hmacAuth } from './worker';
export type { HmacBindings, HmacOptions } from './worker';