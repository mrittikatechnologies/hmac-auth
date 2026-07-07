// src/adapters/memory.ts
// # in-memory adapter (dev/testing)

import type { NonceStore } from './types';

export class MemoryNonceStore implements NonceStore {
  private store = new Map<string, number>(); // nonce -> expiry timestamp

  async checkAndStore(nonce: string, ttlSeconds: number): Promise<boolean> {
    const now = Date.now();

    // Lazy cleanup of expired entries
    for (const [key, expiry] of this.store.entries()) {
      if (expiry < now) this.store.delete(key);
    }

    const key = `nonce:${nonce}`;
    if (this.store.has(key)) return false; // replay detected

    this.store.set(key, now + ttlSeconds * 1000);
    return true;
  }
}