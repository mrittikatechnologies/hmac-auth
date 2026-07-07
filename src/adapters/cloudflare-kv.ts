// # KVNamespace adapter

// src/adapters/cloudflare-kv.ts

import { KVNamespace } from '@cloudflare/workers-types';
import type { NonceStore } from './types';

export class CloudflareKVStore implements NonceStore {
  constructor(private kv: KVNamespace) { }

  async checkAndStore(nonce: string, ttlSeconds: number): Promise<boolean> {
    const key = `nonce:${nonce}`;
    const seen = await this.kv.get(key);

    if (seen) return false; // replay detected

    await this.kv.put(key, '1', { expirationTtl: ttlSeconds });
    return true;
  }
}