// src/adapters/redis.ts
// # Redis adapter (Render, Railway, any Node host)

import type { NonceStore } from './types';

// Accepts any redis client that implements this minimal interface
// Works with: ioredis, @upstash/redis, redis (node-redis), etc.
export interface RedisClient {
  set(
    key: string,
    value: string,
    options: { ex: number; nx: boolean }
  ): Promise<string | null>;
}

export class RedisNonceStore implements NonceStore {
  constructor(private redis: RedisClient) { }

  async checkAndStore(nonce: string, ttlSeconds: number): Promise<boolean> {
    const key = `nonce:${nonce}`;

    // SET key value EX ttl NX — atomic: only sets if key doesn't exist
    // Returns "OK" if set, null if key already existed
    const result = await this.redis.set(key, '1', {
      ex: ttlSeconds,
      nx: true,         // only set if not exists
    });

    return result === 'OK'; // false means replay detected
  }
}