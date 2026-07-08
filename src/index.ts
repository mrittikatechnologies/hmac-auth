// src/index

// Core
export {
  computeHmac,
  buildPayload,
  generateNonce,
  timingSafeEqual,
  isTimestampFresh,
  buildAuthHeaders,
  REPLAY_WINDOW_SEC,
} from './core';

// Client (universal — works everywhere)
export { createWorkerClient } from './client';
export type { WorkerClientConfig, RequestOptions, WorkerResponse } from './client';

// Encryption 
export { importEncryptionKey, encryptData, decryptData } from './encryption';

// Adapter interface + built-in adapters
export type { NonceStore } from './adapters/types';
export { CloudflareKVStore } from './adapters/cloudflare-kv';
export { MemoryNonceStore } from './adapters/memory';
export { RedisNonceStore } from './adapters/redis';
export type { RedisClient } from './adapters/redis';

// Core verify (if someone wants raw access outside Hono)
export { verifyHmacRequest } from './verify';
export type { VerifyOptions, VerifyResult } from './verify';

// Middleware
export { hmacAuthWorker } from './middleware/hono-worker';
export { hmacAuthNode } from './middleware/hono-node';
export type { WorkerBindings } from './middleware/hono-worker';
export type { NodeMiddlewareOptions } from './middleware/hono-node';