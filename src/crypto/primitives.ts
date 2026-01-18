/**
 * Omnituum PQC Shared - Cryptographic Primitives
 *
 * Pure browser implementation - no Node.js dependencies.
 * Uses Web Crypto API and @noble/hashes for all operations.
 */

import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';

// ═══════════════════════════════════════════════════════════════════════════
// TEXT ENCODING
// ═══════════════════════════════════════════════════════════════════════════

export const textEncoder = new TextEncoder();
export const textDecoder = new TextDecoder();

// ═══════════════════════════════════════════════════════════════════════════
// BASE64 UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

export function toB64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function fromB64(str: string): Uint8Array {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ═══════════════════════════════════════════════════════════════════════════
// HEX UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array {
  const s = hex.startsWith('0x') ? hex.slice(2) : hex;
  const normalized = s.length % 2 ? '0' + s : s;
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

export function assertLen(label: string, arr: Uint8Array, n: number): void {
  if (arr.length !== n) {
    throw new Error(`${label} must be ${n} bytes, got ${arr.length}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// RANDOMNESS (Web Crypto API)
// ═══════════════════════════════════════════════════════════════════════════

export function rand32(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(32));
}

export function rand24(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(24));
}

export function rand12(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(12));
}

export function randN(n: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

// ═══════════════════════════════════════════════════════════════════════════
// HASHING (@noble/hashes)
// ═══════════════════════════════════════════════════════════════════════════

export function sha256(bytes: Uint8Array): Uint8Array {
  return nobleSha256(bytes);
}

export function sha256String(str: string): Uint8Array {
  return sha256(textEncoder.encode(str));
}

// ═══════════════════════════════════════════════════════════════════════════
// KEY DERIVATION (HKDF-SHA-256)
// ═══════════════════════════════════════════════════════════════════════════

export function hkdfSha256(
  ikm: Uint8Array,
  opts?: { salt?: Uint8Array; info?: Uint8Array; length?: number }
): Uint8Array {
  const salt = opts?.salt ?? new Uint8Array(32);
  const info = opts?.info ?? new Uint8Array(0);
  const L = opts?.length ?? 32;

  // Extract
  const prk = hmac(nobleSha256, salt, ikm);

  // Expand
  let t = new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  for (let i = 1; i <= Math.ceil(L / 32); i++) {
    const input = new Uint8Array(t.length + info.length + 1);
    input.set(t, 0);
    input.set(info, t.length);
    input[input.length - 1] = i;
    t = new Uint8Array(hmac(nobleSha256, prk, input));
    chunks.push(t);
  }

  const out = new Uint8Array(L);
  let off = 0;
  for (const c of chunks) {
    out.set(c.subarray(0, L - off), off);
    off += c.length;
    if (off >= L) break;
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// CONVENIENCE EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

export const b64 = toB64;
export const ub64 = fromB64;

export const u8 = (s: string | Uint8Array) =>
  typeof s === 'string' ? textEncoder.encode(s) : s;
