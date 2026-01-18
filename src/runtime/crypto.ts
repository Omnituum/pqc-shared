// src/runtime/crypto.ts
// Ensure globalThis.crypto exists across Node + browsers.
// Uses dynamic import so bundlers don't try to resolve Node built-ins.

export async function ensureCrypto(): Promise<void> {
  if (typeof globalThis.crypto !== 'undefined') return;

  // Node: attach WebCrypto at runtime
  const mod: any = await import('node:crypto');
  const webcrypto = mod.webcrypto ?? mod.default?.webcrypto;
  if (!webcrypto) throw new Error('WebCrypto not available in this Node runtime');
  (globalThis as any).crypto = webcrypto as unknown as Crypto;
}

// fire-and-forget (works for your library init pattern)
void ensureCrypto();
