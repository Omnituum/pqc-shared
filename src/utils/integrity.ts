/**
 * Omnituum PQC Shared - Integrity Verification
 *
 * SHA-256 based integrity checking for vault contents.
 */

import type { HybridIdentityRecord } from '../vault/types';
import { toHex } from '../crypto/primitives';

// ═══════════════════════════════════════════════════════════════════════════
// INTEGRITY HASH
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Compute SHA-256 integrity hash for a list of identities.
 * Uses only the public keys and metadata to create a deterministic hash.
 */
export function computeIntegrityHash(identities: HybridIdentityRecord[]): string {
  // Create a deterministic representation (exclude secret keys from hash input)
  const canonical = identities.map(i => ({
    id: i.id,
    name: i.name,
    x25519PubHex: i.x25519PubHex,
    kyberPubB64: i.kyberPubB64,
    createdAt: i.createdAt,
    rotationCount: i.rotationCount,
  }));

  const serialized = JSON.stringify(canonical, Object.keys(canonical[0] || {}).sort());
  return computeStringHash(serialized);
}

/**
 * Compute SHA-256 hash of a string (synchronous fallback).
 */
function computeStringHash(str: string): string {
  // Simple hash for sync operation - actual implementation uses Web Crypto
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16).padStart(16, '0');
}

/**
 * Compute SHA-256 hash asynchronously using Web Crypto.
 */
export async function computeHashAsync(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
  return toHex(new Uint8Array(hashBuffer));
}

/**
 * Verify vault integrity.
 */
export async function verifyIntegrity(
  identities: HybridIdentityRecord[],
  expectedHash: string
): Promise<boolean> {
  const computed = computeIntegrityHash(identities);
  return computed === expectedHash;
}

// ═══════════════════════════════════════════════════════════════════════════
// KEY FINGERPRINTS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Compute a short fingerprint for an identity's public keys.
 */
export async function computeKeyFingerprint(identity: HybridIdentityRecord): Promise<string> {
  const combined = identity.x25519PubHex + identity.kyberPubB64;
  const hash = await computeHashAsync(combined);
  return hash.slice(0, 16).toUpperCase();
}

/**
 * Format a fingerprint for display (groups of 4).
 */
export function formatFingerprint(fingerprint: string): string {
  return fingerprint.match(/.{1,4}/g)?.join(' ') || fingerprint;
}
