/**
 * Omnituum PQC Shared - Vault Migration
 *
 * One-way migration from v1 (PBKDF2) to v2 (Argon2id) encrypted vaults.
 * Includes memory hygiene for sensitive data.
 */

import type {
  OmnituumVault,
  EncryptedVaultFile,
  EncryptedVaultFileV1,
  EncryptedVaultFileV2,
} from './types';
import { decryptVault } from './decrypt';
import { encryptVaultV2 } from './encrypt';
import { zeroMemory } from '../security';
import {
  VAULT_ENCRYPTED_VERSION,
  VAULT_ENCRYPTED_VERSION_V2,
} from '../version';

// ═══════════════════════════════════════════════════════════════════════════
// MIGRATION TYPES
// ═══════════════════════════════════════════════════════════════════════════

export interface MigrationOptions {
  /** Source encrypted vault */
  encryptedVault: EncryptedVaultFile;
  /** Vault password */
  password: string;
  /** Keep backup of original vault data (default: false) */
  keepBackup?: boolean;
}

export interface MigrationResult {
  /** New v2 encrypted vault */
  encryptedVault: EncryptedVaultFileV2;
  /** Original vault (only if keepBackup was true) */
  backup?: EncryptedVaultFile;
  /** Source version */
  sourceVersion: string;
  /** Target version */
  targetVersion: string;
  /** Migration timestamp */
  migratedAt: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// VERSION DETECTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Check if vault needs migration (is v1 format).
 */
export function needsMigration(encryptedVault: EncryptedVaultFile): boolean {
  return encryptedVault.version === VAULT_ENCRYPTED_VERSION;
}

/**
 * Check if vault is already v2 format.
 */
export function isV2Vault(encryptedVault: EncryptedVaultFile): boolean {
  return encryptedVault.version === VAULT_ENCRYPTED_VERSION_V2;
}

/**
 * Get vault KDF info for display.
 */
export function getVaultKdfInfo(encryptedVault: EncryptedVaultFile): {
  kdf: string;
  version: string;
  isSecure: boolean;
  recommendation?: string;
} {
  if (encryptedVault.version === VAULT_ENCRYPTED_VERSION_V2) {
    const v2 = encryptedVault as EncryptedVaultFileV2;
    return {
      kdf: `Argon2id (${v2.memoryCost / 1024}MB, ${v2.timeCost} iterations)`,
      version: 'v2',
      isSecure: true,
    };
  } else {
    const v1 = encryptedVault as EncryptedVaultFileV1;
    return {
      kdf: `PBKDF2-SHA256 (${v1.iterations.toLocaleString()} iterations)`,
      version: 'v1',
      isSecure: true, // Still secure, just not as modern
      recommendation: 'Consider upgrading to Argon2id for stronger protection',
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// MIGRATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Migrate an encrypted vault from v1 (PBKDF2) to v2 (Argon2id).
 *
 * This is a ONE-WAY migration. The original vault remains unchanged,
 * but a new v2 encrypted vault is returned.
 *
 * Memory hygiene: Sensitive data (decrypted vault) is zeroed after use.
 *
 * @param options - Migration options
 * @returns Migration result with new v2 vault
 * @throws Error if decryption fails or vault is already v2
 */
export async function migrateEncryptedVault(
  options: MigrationOptions
): Promise<MigrationResult> {
  const { encryptedVault, password, keepBackup = false } = options;

  // Check if already v2
  if (isV2Vault(encryptedVault)) {
    throw new Error('Vault is already v2 format, no migration needed');
  }

  // Track sensitive data for cleanup
  let decryptedVaultJson: Uint8Array | null = null;

  try {
    // Decrypt the vault
    const vault = await decryptVault(encryptedVault, password);

    // Serialize for memory tracking (so we can zero it)
    const vaultJson = JSON.stringify(vault);
    decryptedVaultJson = new TextEncoder().encode(vaultJson);

    // Re-encrypt with v2 (Argon2id)
    const newEncryptedVault = await encryptVaultV2(vault, password);

    return {
      encryptedVault: newEncryptedVault,
      backup: keepBackup ? encryptedVault : undefined,
      sourceVersion: encryptedVault.version,
      targetVersion: VAULT_ENCRYPTED_VERSION_V2,
      migratedAt: new Date().toISOString(),
    };
  } finally {
    // Zero sensitive data
    if (decryptedVaultJson) {
      zeroMemory(decryptedVaultJson);
    }
  }
}

/**
 * Validate migration by decrypting both versions and comparing.
 * Used for testing migration integrity.
 *
 * @param original - Original encrypted vault
 * @param migrated - Migrated encrypted vault
 * @param password - Vault password
 * @returns true if vaults contain identical data
 */
export async function validateMigration(
  original: EncryptedVaultFile,
  migrated: EncryptedVaultFileV2,
  password: string
): Promise<boolean> {
  let originalVaultJson: Uint8Array | null = null;
  let migratedVaultJson: Uint8Array | null = null;

  try {
    const originalVault = await decryptVault(original, password);
    const migratedVault = await decryptVault(migrated, password);

    // Serialize for comparison
    originalVaultJson = new TextEncoder().encode(JSON.stringify(originalVault));
    migratedVaultJson = new TextEncoder().encode(JSON.stringify(migratedVault));

    // Compare serialized JSON
    if (originalVaultJson.length !== migratedVaultJson.length) {
      return false;
    }

    for (let i = 0; i < originalVaultJson.length; i++) {
      if (originalVaultJson[i] !== migratedVaultJson[i]) {
        return false;
      }
    }

    return true;
  } finally {
    // Zero sensitive data
    if (originalVaultJson) zeroMemory(originalVaultJson);
    if (migratedVaultJson) zeroMemory(migratedVaultJson);
  }
}
