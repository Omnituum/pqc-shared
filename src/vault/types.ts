/**
 * Omnituum PQC Shared - Vault Types
 *
 * Type definitions for the PQC identity vault.
 * FROZEN CONTRACTS - see pqc-docs/specs/vault.v1.md
 */

import type {
  VAULT_VERSION,
  VAULT_ENCRYPTED_VERSION,
  VAULT_ENCRYPTED_VERSION_V2,
  VAULT_KDF,
  VAULT_KDF_V2,
  VAULT_ALGORITHM,
} from '../version';

// ═══════════════════════════════════════════════════════════════════════════
// IDENTITY TYPES
// ═══════════════════════════════════════════════════════════════════════════

export interface HybridIdentityRecord {
  /** Unique identity ID */
  id: string;
  /** Display name */
  name: string;
  /** X25519 public key (hex) */
  x25519PubHex: string;
  /** X25519 secret key (hex) - encrypted in vault */
  x25519SecHex: string;
  /** Kyber public key (base64) */
  kyberPubB64: string;
  /** Kyber secret key (base64) - encrypted in vault */
  kyberSecB64: string;
  /** Creation timestamp */
  createdAt: string;
  /** Last rotation timestamp */
  lastRotatedAt?: string;
  /** Device fingerprint */
  deviceFingerprint?: string;
  /** Key rotation count */
  rotationCount: number;
  /** Identity metadata */
  metadata?: {
    label?: string;
    notes?: string;
    tags?: string[];
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// VAULT TYPES
// ═══════════════════════════════════════════════════════════════════════════

export interface VaultSettings {
  /** Auto-unlock on return (session memory) */
  autoUnlock: boolean;
  /** Last used identity ID */
  lastUsedIdentity?: string;
  /** Lock timeout in minutes (0 = never auto-lock) */
  lockTimeout: number;
  /** Show key fingerprints in UI */
  showFingerprints: boolean;
}

export interface OmnituumVault {
  /** Vault format version (FROZEN - see pqc-docs/specs/vault.v1.md) */
  version: typeof VAULT_VERSION;
  /** Stored identities */
  identities: HybridIdentityRecord[];
  /** Vault settings */
  settings: VaultSettings;
  /** SHA-256 hash of serialized identities (integrity check) */
  integrityHash: string;
  /** Vault creation timestamp */
  createdAt: string;
  /** Last modified timestamp */
  modifiedAt: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCRYPTED VAULT TYPES
// ═══════════════════════════════════════════════════════════════════════════

/** V1 encrypted vault (PBKDF2) */
export interface EncryptedVaultFileV1 {
  /** File format version (FROZEN - see pqc-docs/specs/vault.v1.md) */
  version: typeof VAULT_ENCRYPTED_VERSION;
  /** Key derivation function */
  kdf: typeof VAULT_KDF;
  /** PBKDF2 iterations */
  iterations: number;
  /** Salt (base64) */
  salt: string;
  /** AES-GCM IV (base64) */
  iv: string;
  /** Encrypted vault (base64) */
  ciphertext: string;
  /** Auth tag included in ciphertext (AES-GCM) */
  algorithm: typeof VAULT_ALGORITHM;
}

/** V2 encrypted vault (Argon2id) */
export interface EncryptedVaultFileV2 {
  /** File format version */
  version: typeof VAULT_ENCRYPTED_VERSION_V2;
  /** Key derivation function */
  kdf: typeof VAULT_KDF_V2;
  /** Argon2id memory cost (KiB) */
  memoryCost: number;
  /** Argon2id time cost (iterations) */
  timeCost: number;
  /** Argon2id parallelism */
  parallelism: number;
  /** Salt (base64) */
  salt: string;
  /** AES-GCM IV (base64) */
  iv: string;
  /** Encrypted vault (base64) */
  ciphertext: string;
  /** Auth tag included in ciphertext (AES-GCM) */
  algorithm: typeof VAULT_ALGORITHM;
}

/** Union type for any encrypted vault version */
export type EncryptedVaultFile = EncryptedVaultFileV1 | EncryptedVaultFileV2;

// ═══════════════════════════════════════════════════════════════════════════
// HEALTH CHECK TYPES
// ═══════════════════════════════════════════════════════════════════════════

export type HealthStatus = 'healthy' | 'needs-rotation' | 'warning' | 'error';

export interface IdentityHealth {
  /** Overall health status */
  status: HealthStatus;
  /** Entropy score (0-100) */
  entropyScore: number;
  /** Integrity verified */
  integrityValid: boolean;
  /** SHA-256 fingerprint */
  fingerprint: string;
  /** Days since last rotation */
  daysSinceRotation: number;
  /** Kyber key valid */
  kyberValid: boolean;
  /** X25519 key valid */
  x25519Valid: boolean;
  /** Recommendations */
  recommendations: string[];
}

// ═══════════════════════════════════════════════════════════════════════════
// SESSION TYPES
// ═══════════════════════════════════════════════════════════════════════════

export interface VaultSession {
  /** Session active */
  unlocked: boolean;
  /** Derived encryption key (in memory only) */
  sessionKey: CryptoKey | null;
  /** Unlock timestamp */
  unlockedAt: number | null;
  /** Active identity ID */
  activeIdentityId: string | null;
}

// ═══════════════════════════════════════════════════════════════════════════
// DEFAULT VALUES
// ═══════════════════════════════════════════════════════════════════════════

export const DEFAULT_VAULT_SETTINGS: VaultSettings = {
  autoUnlock: false,
  lockTimeout: 15,
  showFingerprints: true,
};

export const PBKDF2_ITERATIONS = 600000; // OWASP 2023 recommendation
