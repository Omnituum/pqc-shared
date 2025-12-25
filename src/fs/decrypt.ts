/**
 * Omnituum FS - File Decryption
 *
 * Decrypt .oqe (Omnituum Quantum Encrypted) files using hybrid PQC or password.
 */

import nacl from 'tweetnacl';
import {
  fromHex,
  hkdfSha256,
  toB64,
  u8,
} from '../crypto/primitives';
import { kyberDecapsulate, isKyberAvailable } from '../crypto/kyber';
import {
  ALGORITHM_SUITES,
  OQEMetadata,
  HybridDecryptOptions,
  PasswordDecryptOptions,
  DecryptOptions,
  OQEDecryptResult,
  OQEError,
  FileInput,
  toUint8Array,
} from './types';
import { deriveKeyFromPassword, isArgon2Available } from './argon2';
import { aesDecrypt } from './aes';
import {
  parseOQEFile,
  parseHybridKeyMaterial,
  parsePasswordKeyMaterial,
  parseMetadata,
} from './format';

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function hkdfFlex(ikm: Uint8Array, salt: string, info: string): Uint8Array {
  return hkdfSha256(ikm, { salt: u8(salt), info: u8(info), length: 32 });
}

// ═══════════════════════════════════════════════════════════════════════════
// HYBRID MODE DECRYPTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Decrypt an OQE file using hybrid X25519 + Kyber768.
 * Tries Kyber first (post-quantum), falls back to X25519 (classical).
 */
async function decryptHybrid(
  encryptedData: Uint8Array,
  options: HybridDecryptOptions
): Promise<OQEDecryptResult> {
  // Parse file structure
  const { header, keyMaterial, encryptedMetadata, encryptedContent } = parseOQEFile(encryptedData);

  // Verify algorithm
  if (header.algorithmSuite !== ALGORITHM_SUITES.HYBRID_X25519_KYBER768_AES256GCM) {
    throw new OQEError(
      'UNSUPPORTED_ALGORITHM',
      'This file was not encrypted with hybrid mode. Use password decryption.'
    );
  }

  // Parse key material
  const km = parseHybridKeyMaterial(keyMaterial);

  let contentKey: Uint8Array | null = null;

  // Try Kyber first (post-quantum path)
  if (await isKyberAvailable()) {
    try {
      // Kyber decapsulate expects base64 ciphertext
      const kyberShared = await kyberDecapsulate(
        toB64(km.kyberCiphertext),
        options.recipientSecretKeys.kyberSecB64
      );
      const kyberKek = hkdfFlex(kyberShared, 'omnituum/fs/kyber', 'wrap-content-key');
      const unwrapped = nacl.secretbox.open(km.kyberWrappedKey, km.kyberNonce, kyberKek);

      if (unwrapped) {
        contentKey = unwrapped;
        console.log('[OQE] Decrypted content key via Kyber (post-quantum secure)');
      }
    } catch (e) {
      console.warn('[OQE] Kyber decapsulation failed, trying X25519:', e);
    }
  }

  // Fall back to X25519 (classical path)
  if (!contentKey) {
    try {
      const ephPk = km.x25519EphemeralPk;
      const sk = fromHex(options.recipientSecretKeys.x25519SecHex);
      const x25519Shared = nacl.scalarMult(sk, ephPk);
      const x25519Kek = hkdfFlex(x25519Shared, 'omnituum/fs/x25519', 'wrap-content-key');
      const unwrapped = nacl.secretbox.open(km.x25519WrappedKey, km.x25519Nonce, x25519Kek);

      if (unwrapped) {
        contentKey = unwrapped;
        console.log('[OQE] Decrypted content key via X25519 (classical)');
      }
    } catch (e) {
      console.warn('[OQE] X25519 decryption failed:', e);
    }
  }

  if (!contentKey) {
    throw new OQEError('KEY_UNWRAP_FAILED', 'Could not unwrap content key with provided keys');
  }

  // Decrypt metadata
  let metadata: OQEMetadata;
  try {
    const metadataBytes = await aesDecrypt(encryptedMetadata, contentKey, header.iv);
    metadata = parseMetadata(metadataBytes);
  } catch (e) {
    throw new OQEError('DECRYPTION_FAILED', 'Failed to decrypt file metadata');
  }

  // Decrypt file content
  let plaintext: Uint8Array;
  try {
    plaintext = await aesDecrypt(encryptedContent, contentKey, header.iv);
  } catch (e) {
    throw new OQEError('DECRYPTION_FAILED', 'Failed to decrypt file content');
  }

  return {
    data: plaintext,
    filename: metadata.filename,
    mimeType: metadata.mimeType,
    originalSize: metadata.originalSize,
    metadata,
    mode: 'hybrid',
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// PASSWORD MODE DECRYPTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Decrypt an OQE file using password (Argon2id + AES-256-GCM).
 */
async function decryptPassword(
  encryptedData: Uint8Array,
  options: PasswordDecryptOptions
): Promise<OQEDecryptResult> {
  // Verify Argon2 is available
  if (!(await isArgon2Available())) {
    throw new OQEError('ARGON2_UNAVAILABLE', 'Argon2 library not available in this environment');
  }

  // Parse file structure
  const { header, keyMaterial, encryptedMetadata, encryptedContent } = parseOQEFile(encryptedData);

  // Verify algorithm
  if (header.algorithmSuite !== ALGORITHM_SUITES.PASSWORD_ARGON2ID_AES256GCM) {
    throw new OQEError(
      'UNSUPPORTED_ALGORITHM',
      'This file was not encrypted with password mode. Use hybrid decryption.'
    );
  }

  // Parse key material (Argon2 parameters)
  const km = parsePasswordKeyMaterial(keyMaterial);

  // Derive content key from password
  const contentKey = await deriveKeyFromPassword(options.password, km.salt, {
    memoryCost: km.memoryCost,
    timeCost: km.timeCost,
    parallelism: km.parallelism,
    hashLength: 32,
    saltLength: km.salt.length,
  });

  // Decrypt metadata (also verifies password)
  let metadata: OQEMetadata;
  try {
    const metadataBytes = await aesDecrypt(encryptedMetadata, contentKey, header.iv);
    metadata = parseMetadata(metadataBytes);
  } catch (e) {
    throw new OQEError('PASSWORD_WRONG', 'Incorrect password or corrupted file');
  }

  // Decrypt file content
  let plaintext: Uint8Array;
  try {
    plaintext = await aesDecrypt(encryptedContent, contentKey, header.iv);
  } catch (e) {
    throw new OQEError('DECRYPTION_FAILED', 'Failed to decrypt file content');
  }

  return {
    data: plaintext,
    filename: metadata.filename,
    mimeType: metadata.mimeType,
    originalSize: metadata.originalSize,
    metadata,
    mode: 'password',
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN DECRYPTION API
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Decrypt an OQE file.
 *
 * @param encryptedData - Encrypted .oqe file data
 * @param options - Decryption options (hybrid or password mode)
 * @returns Decrypted file result
 *
 * @example
 * // Hybrid mode (with identity)
 * const result = await decryptFile(oqeData, {
 *   mode: 'hybrid',
 *   recipientSecretKeys: identity.getSecretKeys(),
 * });
 *
 * @example
 * // Password mode
 * const result = await decryptFile(oqeData, {
 *   mode: 'password',
 *   password: 'my-secure-password',
 * });
 */
export async function decryptFile(
  encryptedData: FileInput,
  options: DecryptOptions
): Promise<OQEDecryptResult> {
  const data = await toUint8Array(encryptedData);

  if (options.mode === 'hybrid') {
    return decryptHybrid(data, options);
  } else {
    return decryptPassword(data, options);
  }
}

/**
 * Decrypt a file encrypted for self.
 * Convenience method for personal file decryption.
 */
export async function decryptFileForSelf(
  encryptedData: FileInput,
  identity: {
    x25519SecHex: string;
    kyberSecB64: string;
  }
): Promise<OQEDecryptResult> {
  return decryptFile(encryptedData, {
    mode: 'hybrid',
    recipientSecretKeys: {
      x25519SecHex: identity.x25519SecHex,
      kyberSecB64: identity.kyberSecB64,
    },
  });
}

/**
 * Quick decrypt with password (simple API).
 */
export async function decryptFileWithPassword(
  encryptedData: FileInput,
  password: string
): Promise<OQEDecryptResult> {
  return decryptFile(encryptedData, {
    mode: 'password',
    password,
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// FILE INSPECTION (without decryption)
// ═══════════════════════════════════════════════════════════════════════════

export interface OQEFileInfo {
  /** Format version */
  version: number;
  /** Encryption mode */
  mode: 'hybrid' | 'password';
  /** Algorithm name */
  algorithm: string;
  /** Can decrypt with Kyber (for hybrid mode) */
  supportsKyber: boolean;
  /** File size */
  fileSize: number;
}

/**
 * Inspect an OQE file without decrypting it.
 * Useful for determining what credentials are needed.
 */
export async function inspectOQEFile(data: FileInput): Promise<OQEFileInfo> {
  const bytes = await toUint8Array(data);
  const { header } = parseOQEFile(bytes);

  let mode: 'hybrid' | 'password';
  let algorithm: string;

  if (header.algorithmSuite === ALGORITHM_SUITES.HYBRID_X25519_KYBER768_AES256GCM) {
    mode = 'hybrid';
    algorithm = 'X25519 + Kyber768 + AES-256-GCM';
  } else {
    mode = 'password';
    algorithm = 'Argon2id + AES-256-GCM';
  }

  return {
    version: header.version,
    mode,
    algorithm,
    supportsKyber: mode === 'hybrid' && (await isKyberAvailable()),
    fileSize: bytes.length,
  };
}
