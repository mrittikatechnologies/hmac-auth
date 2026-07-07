// packages/hmac-auth/src/core.ts
// # crypto logic — unchanged, works everywhere

export const REPLAY_WINDOW_SEC = 120;
export const NONCE_REGEX = /^[a-f0-9]{32}$/;

export interface HmacHeaders {
  'X-Signature': string;
  'X-Timestamp': string;
  'X-Nonce': string;
}

export interface VerifyResult {
  valid: boolean;
  reason?: string;
}

// Works identically on Bun and Cloudflare Workers (both use Web Crypto API)
export async function computeHmac(secret: string, payload: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuffer = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(payload)
  );
  return Array.from(new Uint8Array(sigBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function buildPayload(
  timestamp: string,
  nonce: string,
  method: string,
  path: string,
  body: string
): string {
  return `${timestamp}.${nonce}.${method}.${path}.${body}`;
}

// Constant-time comparison to prevent timing attacks
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

export function generateNonce(): string {
  return crypto.randomUUID().replace(/-/g, '');
}

export function isTimestampFresh(timestamp: string): boolean {
  const age = Date.now() - parseInt(timestamp, 10);
  return !isNaN(age) && age <= REPLAY_WINDOW_SEC * 1000 && age > -5000;
}

export function buildAuthHeaders(
  signature: string,
  timestamp: string,
  nonce: string
): HmacHeaders {
  return {
    'X-Signature': signature,
    'X-Timestamp': timestamp,
    'X-Nonce': nonce,
  };
}