/**
 * Omnituum PQC Shared - Version Constants & Guards
 *
 * FROZEN CONTRACTS: These version strings define the wire format.
 * Breaking changes require a version bump.
 *
 * @see pqc-docs/specs/envelope.v1.md
 * @see pqc-docs/specs/vault.v1.md
 * @see pqc-docs/specs/identity.v1.md
 */

import {
  OMNI_VERSIONS,
  DEPRECATED_VERSIONS,
} from '@omnituum/envelope-registry';

// ═══════════════════════════════════════════════════════════════════════════
// VERSION CONSTANTS (FROZEN)
// ═══════════════════════════════════════════════════════════════════════════

/** HybridEnvelope version - hybrid encryption format (from registry) */
export const ENVELOPE_VERSION = OMNI_VERSIONS.HYBRID_V1;

/** Legacy envelope version for backwards compatibility (from registry) */
export const ENVELOPE_VERSION_LEGACY = DEPRECATED_VERSIONS.PQC_DEMO_HYBRID_V1;

/** OmnituumVault version - decrypted vault format */
export const VAULT_VERSION = 'omnituum.vault.v1' as const;

/** EncryptedVaultFile version - encrypted vault format (PBKDF2) */
export const VAULT_ENCRYPTED_VERSION = 'omnituum.vault.enc.v1' as const;

/** EncryptedVaultFile v2 - encrypted vault format (Argon2id) */
export const VAULT_ENCRYPTED_VERSION_V2 = 'omnituum.vault.enc.v2' as const;

/** Algorithm suite for hybrid encryption */
export const ENVELOPE_SUITE = 'x25519+kyber768' as const;

/** AEAD algorithm for envelope content */
export const ENVELOPE_AEAD = 'xsalsa20poly1305' as const;

/** KDF for vault encryption (v1) */
export const VAULT_KDF = 'PBKDF2-SHA256' as const;

/** KDF for vault encryption (v2) */
export const VAULT_KDF_V2 = 'Argon2id' as const;

/** Encryption algorithm for vault */
export const VAULT_ALGORITHM = 'AES-256-GCM' as const;

// ═══════════════════════════════════════════════════════════════════════════
// SUPPORTED VERSIONS (for reading)
// ═══════════════════════════════════════════════════════════════════════════

/** Envelope versions we can read */
export const SUPPORTED_ENVELOPE_VERSIONS = [
  ENVELOPE_VERSION,
  ENVELOPE_VERSION_LEGACY,
] as const;

/** Vault versions we can read */
export const SUPPORTED_VAULT_VERSIONS = [
  VAULT_VERSION,
] as const;

/** Encrypted vault versions we can read */
export const SUPPORTED_VAULT_ENCRYPTED_VERSIONS = [
  VAULT_ENCRYPTED_VERSION,
  VAULT_ENCRYPTED_VERSION_V2,
] as const;

// ═══════════════════════════════════════════════════════════════════════════
// VERSION GUARD ERRORS
// ═══════════════════════════════════════════════════════════════════════════

export class VersionMismatchError extends Error {
  constructor(
    public readonly type: 'envelope' | 'vault' | 'vault_encrypted',
    public readonly expected: readonly string[],
    public readonly received: string
  ) {
    super(
      `Version mismatch for ${type}: expected one of [${expected.join(', ')}], got "${received}". ` +
      `This may indicate data corruption or a newer format. ` +
      `See pqc-docs/specs/ for format specifications.`
    );
    this.name = 'VersionMismatchError';
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// VERSION GUARDS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Assert envelope version is supported.
 * Throws VersionMismatchError if not.
 */
export function assertEnvelopeVersion(version: string): void {
  if (!SUPPORTED_ENVELOPE_VERSIONS.includes(version as typeof SUPPORTED_ENVELOPE_VERSIONS[number])) {
    throw new VersionMismatchError('envelope', SUPPORTED_ENVELOPE_VERSIONS, version);
  }
}

/**
 * Assert vault version is supported.
 * Throws VersionMismatchError if not.
 */
export function assertVaultVersion(version: string): void {
  if (!SUPPORTED_VAULT_VERSIONS.includes(version as typeof SUPPORTED_VAULT_VERSIONS[number])) {
    throw new VersionMismatchError('vault', SUPPORTED_VAULT_VERSIONS, version);
  }
}

/**
 * Assert encrypted vault version is supported.
 * Throws VersionMismatchError if not.
 */
export function assertVaultEncryptedVersion(version: string): void {
  if (!SUPPORTED_VAULT_ENCRYPTED_VERSIONS.includes(version as typeof SUPPORTED_VAULT_ENCRYPTED_VERSIONS[number])) {
    throw new VersionMismatchError('vault_encrypted', SUPPORTED_VAULT_ENCRYPTED_VERSIONS, version);
  }
}

/**
 * Check if envelope version is supported (non-throwing).
 */
export function isEnvelopeVersionSupported(version: string): boolean {
  return SUPPORTED_ENVELOPE_VERSIONS.includes(version as typeof SUPPORTED_ENVELOPE_VERSIONS[number]);
}

/**
 * Check if vault version is supported (non-throwing).
 */
export function isVaultVersionSupported(version: string): boolean {
  return SUPPORTED_VAULT_VERSIONS.includes(version as typeof SUPPORTED_VAULT_VERSIONS[number]);
}

/**
 * Check if encrypted vault version is supported (non-throwing).
 */
export function isVaultEncryptedVersionSupported(version: string): boolean {
  return SUPPORTED_VAULT_ENCRYPTED_VERSIONS.includes(version as typeof SUPPORTED_VAULT_ENCRYPTED_VERSIONS[number]);
}

// ═══════════════════════════════════════════════════════════════════════════
// ENVELOPE VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Validate envelope structure and version.
 * Returns detailed validation result.
 */
export function validateEnvelope(envelope: unknown): {
  valid: boolean;
  version?: string;
  errors: string[];
} {
  const errors: string[] = [];

  if (!envelope || typeof envelope !== 'object') {
    return { valid: false, errors: ['Envelope must be an object'] };
  }

  const env = envelope as Record<string, unknown>;

  // Version check
  if (typeof env.v !== 'string') {
    errors.push('Missing or invalid version field "v"');
  } else if (!isEnvelopeVersionSupported(env.v)) {
    errors.push(`Unsupported envelope version: ${env.v}`);
  }

  // Suite check
  if (env.suite !== ENVELOPE_SUITE) {
    errors.push(`Invalid suite: expected "${ENVELOPE_SUITE}", got "${env.suite}"`);
  }

  // AEAD check
  if (env.aead !== ENVELOPE_AEAD) {
    errors.push(`Invalid aead: expected "${ENVELOPE_AEAD}", got "${env.aead}"`);
  }

  // Required fields
  const required = ['x25519Epk', 'x25519Wrap', 'kyberKemCt', 'kyberWrap', 'contentNonce', 'ciphertext', 'meta'];
  for (const field of required) {
    if (!(field in env)) {
      errors.push(`Missing required field: ${field}`);
    }
  }

  return {
    valid: errors.length === 0,
    version: typeof env.v === 'string' ? env.v : undefined,
    errors,
  };
}

/**
 * Validate vault structure and version.
 */
export function validateVault(vault: unknown): {
  valid: boolean;
  version?: string;
  errors: string[];
} {
  const errors: string[] = [];

  if (!vault || typeof vault !== 'object') {
    return { valid: false, errors: ['Vault must be an object'] };
  }

  const v = vault as Record<string, unknown>;

  // Version check
  if (typeof v.version !== 'string') {
    errors.push('Missing or invalid version field');
  } else if (!isVaultVersionSupported(v.version)) {
    errors.push(`Unsupported vault version: ${v.version}`);
  }

  // Required fields
  if (!Array.isArray(v.identities)) {
    errors.push('Missing or invalid identities array');
  }

  if (!v.settings || typeof v.settings !== 'object') {
    errors.push('Missing or invalid settings object');
  }

  if (typeof v.integrityHash !== 'string') {
    errors.push('Missing or invalid integrityHash');
  }

  if (typeof v.createdAt !== 'string') {
    errors.push('Missing or invalid createdAt timestamp');
  }

  if (typeof v.modifiedAt !== 'string') {
    errors.push('Missing or invalid modifiedAt timestamp');
  }

  return {
    valid: errors.length === 0,
    version: typeof v.version === 'string' ? v.version : undefined,
    errors,
  };
}

/**
 * Validate encrypted vault structure and version.
 */
export function validateEncryptedVault(encVault: unknown): {
  valid: boolean;
  version?: string;
  errors: string[];
} {
  const errors: string[] = [];

  if (!encVault || typeof encVault !== 'object') {
    return { valid: false, errors: ['Encrypted vault must be an object'] };
  }

  const v = encVault as Record<string, unknown>;

  // Version check
  if (typeof v.version !== 'string') {
    errors.push('Missing or invalid version field');
  } else if (!isVaultEncryptedVersionSupported(v.version)) {
    errors.push(`Unsupported encrypted vault version: ${v.version}`);
  }

  // KDF check (v1 uses PBKDF2, v2 uses Argon2id)
  if (v.version === VAULT_ENCRYPTED_VERSION && v.kdf !== VAULT_KDF) {
    errors.push(`Invalid kdf for v1: expected "${VAULT_KDF}", got "${v.kdf}"`);
  } else if (v.version === VAULT_ENCRYPTED_VERSION_V2 && v.kdf !== VAULT_KDF_V2) {
    errors.push(`Invalid kdf for v2: expected "${VAULT_KDF_V2}", got "${v.kdf}"`);
  } else if (v.kdf !== VAULT_KDF && v.kdf !== VAULT_KDF_V2) {
    errors.push(`Unsupported kdf: ${v.kdf}`);
  }

  // Algorithm check
  if (v.algorithm !== VAULT_ALGORITHM) {
    errors.push(`Invalid algorithm: expected "${VAULT_ALGORITHM}", got "${v.algorithm}"`);
  }

  // Required fields
  if (typeof v.iterations !== 'number' || v.iterations < 1) {
    errors.push('Missing or invalid iterations');
  }

  if (typeof v.salt !== 'string') {
    errors.push('Missing or invalid salt');
  }

  if (typeof v.iv !== 'string') {
    errors.push('Missing or invalid iv');
  }

  if (typeof v.ciphertext !== 'string') {
    errors.push('Missing or invalid ciphertext');
  }

  return {
    valid: errors.length === 0,
    version: typeof v.version === 'string' ? v.version : undefined,
    errors,
  };
}
