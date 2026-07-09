/**
 * Omnituum PQC Shared - Integrity Verification
 *
 * SHA-256 checksum over a vault's public identity records.
 *
 * SCOPE: this is an UNKEYED integrity checksum — it detects accidental
 * corruption or field mix-ups, not malicious tampering. An attacker who edits
 * the decrypted vault can simply recompute this value. Tamper *resistance* for
 * a stored vault comes from the AES-256-GCM authentication tag on the encrypted
 * file (see vault/encrypt.ts), not from this hash. Do not treat a matching
 * integrity hash as authentication.
 */

import type { HybridIdentityRecord } from '../vault/types';
import { sha256, toHex, textEncoder } from '../crypto/primitives';

// ═══════════════════════════════════════════════════════════════════════════
// INTEGRITY HASH
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Compute a SHA-256 checksum for a list of identities.
 * Uses only the public keys and metadata (never secret keys). Deterministic:
 * the canonical objects carry a fixed key order, which JSON.stringify preserves.
 */
export function computeIntegrityHash(identities: HybridIdentityRecord[]): string {
  const canonical = identities.map(i => ({
    id: i.id,
    name: i.name,
    x25519PubHex: i.x25519PubHex,
    kyberPubB64: i.kyberPubB64,
    createdAt: i.createdAt,
    rotationCount: i.rotationCount,
  }));

  const serialized = JSON.stringify(canonical);
  return computeStringHash(serialized);
}

/**
 * Real SHA-256 of a UTF-8 string, returned as lowercase hex. Synchronous via
 * @noble/hashes (no Web Crypto async dependency).
 */
function computeStringHash(str: string): string {
  return toHex(sha256(textEncoder.encode(str)));
}

/**
 * Compute SHA-256 hash asynchronously using Web Crypto or Node fallback.
 */
export async function computeHashAsync(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(data);

  // Browser/WebCrypto path
  const subtle = globalThis.crypto?.subtle;
  if (subtle) {
    const hashBuffer = await subtle.digest('SHA-256', bytes);
    return toHex(new Uint8Array(hashBuffer));
  }

  // Node fallback (always available, no async shim dependency)
  const { createHash } = await import('node:crypto');
  return toHex(new Uint8Array(createHash('sha256').update(bytes).digest()));
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
