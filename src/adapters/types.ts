// src/adapters/types.ts
// # adapter types — define the interface for different runtime environments
// # NonceStore interface (the contract)


export interface NonceStore {
  // Returns true if nonce was fresh (not seen before) and marks it as used
  // Returns false if nonce was already seen (replay)
  checkAndStore(nonce: string, ttlSeconds: number): Promise<boolean>;
}