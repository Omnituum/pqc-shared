/**
 * Omnituum FS - File Encryption Module
 *
 * Post-quantum secure file encryption for any file type.
 * Supports two modes:
 * - Hybrid: X25519 + Kyber768 + AES-256-GCM (identity-based)
 * - Password: Argon2id + AES-256-GCM (standalone)
 *
 * @example
 * // Encrypt with hybrid mode (using identity)
 * import { encryptFile, decryptFile } from '@omnituum/pqc-shared/fs';
 *
 * const encrypted = await encryptFile(
 *   { data: fileBytes, filename: 'secret.pdf' },
 *   { mode: 'hybrid', recipientPublicKeys: identity.getPublicKeys() }
 * );
 *
 * // Download encrypted file
 * downloadEncryptedFile(encrypted);
 *
 * @example
 * // Encrypt with password (standalone)
 * const encrypted = await encryptFileWithPassword(
 *   { data: fileBytes, filename: 'secret.pdf' },
 *   'my-secure-password'
 * );
 */

// Types
export * from './types';

// Argon2id key derivation
export {
  deriveKeyFromPassword,
  generateArgon2Salt,
  verifyPassword,
  estimateArgon2Params,
  benchmarkArgon2,
  isArgon2Available,
  DEFAULT_ARGON2ID_PARAMS,
  MIN_ARGON2ID_PARAMS,
} from './argon2';

// AES-256-GCM encryption
export {
  AES_KEY_SIZE,
  AES_GCM_IV_SIZE,
  AES_GCM_TAG_SIZE,
  importAesKey,
  generateAesKey,
  exportAesKey,
  aesEncrypt,
  aesEncryptCombined,
  aesDecrypt,
  aesDecryptCombined,
  aesEncryptStreaming,
  aesDecryptStreaming,
  STREAM_CHUNK_SIZE,
} from './aes';

// OQE format operations
export {
  writeOQEHeader,
  parseOQEHeader,
  serializeHybridKeyMaterial,
  parseHybridKeyMaterial,
  serializePasswordKeyMaterial,
  parsePasswordKeyMaterial,
  serializeMetadata,
  parseMetadata,
  assembleOQEFile,
  parseOQEFile,
  OQE_EXTENSION,
  addOQEExtension,
  removeOQEExtension,
  isOQEFile,
  OQE_MIME_TYPE,
  getAlgorithmName,
} from './format';

// Main encryption API
export {
  encryptFile,
  encryptFileForSelf,
  encryptFileWithPassword,
} from './encrypt';

// Main decryption API
export {
  decryptFile,
  decryptFileForSelf,
  decryptFileWithPassword,
  inspectOQEFile,
} from './decrypt';

// Browser utilities
export {
  downloadEncryptedFile,
  downloadDecryptedFile,
  downloadBlob,
  downloadBytes,
  readFile,
  readFileAsText,
  readFileAsDataURL,
  createDropZone,
  openFilePicker,
  openOQEFilePicker,
  openFileToEncrypt,
  encryptResultToBlob,
  decryptResultToBlob,
  createObjectURL,
  bytesToDataURL,
  getFileInfo,
  formatFileSize,
  copyToClipboard,
  isBrowser,
  isWebCryptoAvailable,
  isFileAPIAvailable,
  isDragDropSupported,
} from './browser';

// Re-export key types for convenience
export type {
  OQEMode,
  AlgorithmSuiteId,
  Argon2idParams,
  OQEMetadata,
  OQEHeader,
  HybridKeyMaterial,
  PasswordKeyMaterial,
  HybridEncryptOptions,
  PasswordEncryptOptions,
  EncryptOptions,
  HybridDecryptOptions,
  PasswordDecryptOptions,
  DecryptOptions,
  OQEEncryptResult,
  OQEDecryptResult,
  OQEErrorCode,
  ProgressCallback,
  FileInput,
} from './types';

export { OQEError } from './types';
