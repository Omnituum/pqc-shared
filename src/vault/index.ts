/**
 * Omnituum PQC Shared - Vault Exports
 */

// Types
export type {
  HybridIdentityRecord,
  VaultSettings,
  OmnituumVault,
  EncryptedVaultFile,
  EncryptedVaultFileV1,
  EncryptedVaultFileV2,
  HealthStatus,
  IdentityHealth,
  VaultSession,
} from './types';

export {
  DEFAULT_VAULT_SETTINGS,
  PBKDF2_ITERATIONS,
} from './types';

// Encryption
export {
  deriveKey,
  encryptVault,
  encryptVaultV2,
  encryptVaultToBlob,
  encryptVaultToDataURL,
} from './encrypt';

// Decryption
export {
  decryptVault,
  decryptVaultFromJson,
  decryptVaultFromFile,
  isValidEncryptedVaultFile,
} from './decrypt';

// Manager
export {
  createEmptyVault,
  createIdentity,
  addIdentity,
  removeIdentity,
  rotateIdentityKeys,
  updateIdentityMetadata,
  updateSettings,
  setActiveIdentity,
  exportVault,
  importVault,
  downloadVault,
  getSession,
  unlockSession,
  lockSession,
  setSessionActiveIdentity,
} from './manager';

// Migration
export type {
  MigrationOptions,
  MigrationResult,
} from './migrate';

export {
  needsMigration,
  isV2Vault,
  getVaultKdfInfo,
  migrateEncryptedVault,
  validateMigration,
} from './migrate';
