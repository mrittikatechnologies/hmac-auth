// src/verify.ts
// # framework-agnostic verify logic

import {
  computeHmac,
  buildPayload,
  timingSafeEqual,
  isTimestampFresh,
  NONCE_REGEX,
  REPLAY_WINDOW_SEC,
} from './core';
import type { NonceStore } from './adapters/types';

export interface VerifyOptions {
  secret: string;
  nonceStore: NonceStore;
  signature: string;
  timestamp: string;
  nonce: string;
  method: string;
  path: string;
  body: string;
}

export type VerifyResult =
  | { valid: true }
  | { valid: false; reason: string };

export async function verifyHmacRequest(opts: VerifyOptions): Promise<VerifyResult> {
  const { secret, nonceStore, signature, timestamp, nonce, method, path, body } = opts;

  // 1. Presence check
  if (!signature || !timestamp || !nonce) {
    return { valid: false, reason: 'missing_headers' };
  }

  // 2. Nonce format guard — before any I/O
  if (!NONCE_REGEX.test(nonce)) {
    return { valid: false, reason: 'malformed_nonce' };
  }

  // 3. Timestamp freshness — cheap, no I/O
  if (!isTimestampFresh(timestamp)) {
    return { valid: false, reason: 'stale_timestamp' };
  }

  // 4. Signature verification — CPU only, no I/O
  const payload = buildPayload(timestamp, nonce, method, path, body);
  const expected = await computeHmac(secret, payload);

  if (!timingSafeEqual(signature, expected)) {
    return { valid: false, reason: 'invalid_signature' };
  }

  // 5. Replay check — I/O only after everything else passes
  const fresh = await nonceStore.checkAndStore(nonce, REPLAY_WINDOW_SEC);
  if (!fresh) {
    return { valid: false, reason: 'replay_detected' };
  }

  return { valid: true };
}