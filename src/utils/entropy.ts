/**
 * Omnituum PQC Shared - Entropy & Randomness Utilities
 *
 * Functions for generating secure random values and measuring entropy.
 */

// ═══════════════════════════════════════════════════════════════════════════
// ID GENERATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Generate a cryptographically secure random ID.
 */
export function generateId(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate a short random ID (8 characters).
 */
export function generateShortId(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(4));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ═══════════════════════════════════════════════════════════════════════════
// ENTROPY MEASUREMENT
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Calculate Shannon entropy of a byte array.
 * Returns bits per byte (max 8.0 for perfect randomness).
 */
export function calculateShannonEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;

  // Count byte frequencies
  const freq = new Map<number, number>();
  for (const byte of bytes) {
    freq.set(byte, (freq.get(byte) || 0) + 1);
  }

  // Calculate entropy
  let entropy = 0;
  const len = bytes.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Calculate entropy score (0-100) for key material.
 * 100 = perfect entropy, 0 = no entropy.
 */
export function calculateEntropyScore(hexKey: string): number {
  // Convert hex to bytes
  const clean = hexKey.startsWith('0x') ? hexKey.slice(2) : hexKey;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }

  // Calculate Shannon entropy
  const entropy = calculateShannonEntropy(bytes);

  // Convert to 0-100 score (8.0 bits/byte = 100%)
  return Math.min(100, Math.round((entropy / 8.0) * 100));
}

/**
 * Check if a key has sufficient entropy.
 */
export function hasGoodEntropy(hexKey: string, threshold: number = 70): boolean {
  return calculateEntropyScore(hexKey) >= threshold;
}

// ═══════════════════════════════════════════════════════════════════════════
// KEY VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Validate X25519 public key format.
 */
export function isValidX25519Key(hexKey: string): boolean {
  const clean = hexKey.startsWith('0x') ? hexKey.slice(2) : hexKey;
  return /^[0-9a-fA-F]{64}$/.test(clean);
}

/**
 * Validate Kyber public key format (base64, ~1568 bytes for ML-KEM-768).
 */
export function isValidKyberKey(b64Key: string): boolean {
  try {
    const decoded = atob(b64Key);
    // ML-KEM-768 public key is 1184 bytes
    return decoded.length >= 1000 && decoded.length <= 1500;
  } catch {
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// ROTATION AGE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Calculate days since last rotation.
 */
export function daysSinceRotation(lastRotatedAt?: string, createdAt?: string): number {
  const dateStr = lastRotatedAt || createdAt;
  if (!dateStr) return 0;

  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  return Math.floor(diffMs / (1000 * 60 * 60 * 24));
}

/**
 * Check if keys should be rotated (default: 90 days).
 */
export function shouldRotate(lastRotatedAt?: string, createdAt?: string, maxDays: number = 90): boolean {
  return daysSinceRotation(lastRotatedAt, createdAt) >= maxDays;
}
