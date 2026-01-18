// src/runtime/crypto.ts
// Ensure globalThis.crypto exists across Node + browsers.

import { webcrypto as nodeWebcrypto } from 'crypto';

export function ensureCrypto(): void {
  // Browser already has it
  if (typeof globalThis.crypto !== 'undefined') return;

  // Node: attach WebCrypto
  (globalThis as any).crypto = nodeWebcrypto as unknown as Crypto;
}

// Run on import
ensureCrypto();
