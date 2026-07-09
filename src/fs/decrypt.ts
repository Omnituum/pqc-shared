/**
 * Omnituum FS - File Decryption
 *
 * Decrypt .oqe (Omnituum Quantum Encrypted) files using hybrid PQC or password.
 */

import nacl from 'tweetnacl';
import {
  fromHex,
  toHex,
  hkdfSha256,
  toB64,
  b64,
  u8,
} from '../crypto/primitives';
import { kyberDecapsulate, isKyberAvailable } from '../crypto/kyber';
import {
  ALGORITHM_SUITES,
  OQE_FORMAT_VERSION_V2,
  OQEHeader,
  OQEMetadata,
  HybridDecryptOptions,
  PasswordDecryptOptions,
  DecryptOptions,
  OQEDecryptResult,
  OQEError,
  FileInput,
  toUint8Array,
} from './types';
import { combinedFileKekV2 } from './encrypt';
import { deriveKeyFromPassword, isArgon2Available } from './argon2';
import { aesDecrypt } from './aes';
import {
  parseOQEFile,
  parseHybridKeyMaterial,
  parseHybridKeyMaterialV2,
  parsePasswordKeyMaterial,
  parseMetadata,
  writeOQEHeader,
} from './format';

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function hkdfFlex(ikm: Uint8Array, salt: string, info: string): Uint8Array {
  return hkdfSha256(ikm, { salt: u8(salt), info: u8(info), length: 32 });
}

/**
 * Reconstruct the AEAD associated data for a parsed v2 header. Re-serializing
 * the parsed header yields the exact bytes bound at encryption time, so any
 * mutation of version/suite/flags/lengths/IVs makes AES-GCM authentication fail.
 */
function headerAad(header: OQEHeader): Uint8Array {
  return writeOQEHeader(header);
}

// ═══════════════════════════════════════════════════════════════════════════
// HYBRID MODE DECRYPTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Decrypt an OQE hybrid file. Dispatches by suite:
 * - v2 (ML-KEM-1024, suite 0x03): single AND-combined KEK — both the X25519 and
 *   ML-KEM secrets are required and there is no per-primitive fallback.
 * - v1 legacy (Kyber, suite 0x01): read-only compatibility path where either
 *   secret alone unwraps the content key (the weakness v2 exists to fix).
 */
async function decryptHybrid(
  encryptedData: Uint8Array,
  options: HybridDecryptOptions
): Promise<OQEDecryptResult> {
  const parsed = parseOQEFile(encryptedData);
  const { header } = parsed;

  if (header.algorithmSuite === ALGORITHM_SUITES.HYBRID_X25519_MLKEM1024_AES256GCM) {
    return decryptHybridV2(parsed, options);
  }
  if (header.algorithmSuite === ALGORITHM_SUITES.HYBRID_X25519_KYBER768_AES256GCM) {
    return decryptHybridV1Legacy(parsed, options);
  }
  throw new OQEError(
    'UNSUPPORTED_ALGORITHM',
    'This file was not encrypted with hybrid mode. Use password decryption.'
  );
}

type ParsedFile = ReturnType<typeof parseOQEFile>;

/** v2 AND-combined hybrid decryption (both secrets required, header AAD-bound). */
async function decryptHybridV2(
  parsed: ParsedFile,
  options: HybridDecryptOptions
): Promise<OQEDecryptResult> {
  const { header, keyMaterial, encryptedMetadata, encryptedContent } = parsed;
  if (header.version !== OQE_FORMAT_VERSION_V2 || !header.contentIv) {
    throw new OQEError('INVALID_HEADER', 'v2 hybrid file missing content IV');
  }

  const km = parseHybridKeyMaterialV2(keyMaterial);
  // Must match encryptHybrid's transcript exactly: plain hex, no "0x" prefix.
  const x25519EpkHex = toHex(km.x25519EphemeralPk);
  const kyberKemCtB64 = b64(km.kyberCiphertext);

  // ML-KEM decapsulation (post-quantum half). No classical fallback in v2.
  const kyberShared = await kyberDecapsulate(kyberKemCtB64, options.recipientSecretKeys.kyberSecB64);

  // X25519 ECDH (classical half).
  const sk = fromHex(options.recipientSecretKeys.x25519SecHex);
  const x25519Shared = nacl.scalarMult(sk, km.x25519EphemeralPk);

  const kek = combinedFileKekV2(kyberShared, x25519Shared, x25519EpkHex, kyberKemCtB64);
  kyberShared.fill(0);
  x25519Shared.fill(0);

  const contentKey = nacl.secretbox.open(km.ckWrapped, km.ckWrapNonce, kek);
  kek.fill(0);
  if (!contentKey) {
    throw new OQEError('KEY_UNWRAP_FAILED', 'Could not unwrap content key — combined-KEK authentication failed');
  }

  const aad = headerAad(header);
  try {
    const metadata = await decryptSection(encryptedMetadata, contentKey, header.iv, aad, 'metadata');
    const plaintext = await aesDecrypt(encryptedContent, contentKey, header.contentIv, aad);
    return buildResult(plaintext, metadata, 'hybrid');
  } finally {
    contentKey.fill(0);
  }
}

/** LEGACY read-only: v1 either-key hybrid. Single IV, no AAD. */
async function decryptHybridV1Legacy(
  parsed: ParsedFile,
  options: HybridDecryptOptions
): Promise<OQEDecryptResult> {
  const { header, keyMaterial, encryptedMetadata, encryptedContent } = parsed;
  const km = parseHybridKeyMaterial(keyMaterial);

  let contentKey: Uint8Array | null = null;

  if (await isKyberAvailable()) {
    try {
      const kyberShared = await kyberDecapsulate(
        toB64(km.kyberCiphertext),
        options.recipientSecretKeys.kyberSecB64
      );
      const kyberKek = hkdfFlex(kyberShared, 'omnituum/fs/kyber', 'wrap-content-key');
      contentKey = nacl.secretbox.open(km.kyberWrappedKey, km.kyberNonce, kyberKek);
    } catch {
      // Fall through to the classical wrap.
    }
  }

  if (!contentKey) {
    try {
      const sk = fromHex(options.recipientSecretKeys.x25519SecHex);
      const x25519Shared = nacl.scalarMult(sk, km.x25519EphemeralPk);
      const x25519Kek = hkdfFlex(x25519Shared, 'omnituum/fs/x25519', 'wrap-content-key');
      contentKey = nacl.secretbox.open(km.x25519WrappedKey, km.x25519Nonce, x25519Kek);
    } catch {
      // Handled below.
    }
  }

  if (!contentKey) {
    throw new OQEError('KEY_UNWRAP_FAILED', 'Could not unwrap content key with provided keys');
  }

  try {
    // v1 reused header.iv for both sections; preserved for read compatibility.
    const metadata = await decryptSection(encryptedMetadata, contentKey, header.iv, undefined, 'metadata');
    const plaintext = await aesDecrypt(encryptedContent, contentKey, header.iv);
    return buildResult(plaintext, metadata, 'hybrid');
  } finally {
    contentKey.fill(0);
  }
}

async function decryptSection(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array | undefined,
  what: 'metadata'
): Promise<OQEMetadata> {
  try {
    const bytes = await aesDecrypt(ciphertext, key, iv, aad);
    return parseMetadata(bytes);
  } catch {
    throw new OQEError('DECRYPTION_FAILED', `Failed to decrypt file ${what}`);
  }
}

function buildResult(
  plaintext: Uint8Array,
  metadata: OQEMetadata,
  mode: 'hybrid' | 'password'
): OQEDecryptResult {
  return {
    data: plaintext,
    filename: metadata.filename,
    mimeType: metadata.mimeType,
    originalSize: metadata.originalSize,
    metadata,
    mode,
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

  // v2 binds the header as AAD and uses a distinct content IV; v1 reused
  // header.iv for both sections and had no AAD.
  const isV2 = header.version === OQE_FORMAT_VERSION_V2;
  const aad = isV2 ? headerAad(header) : undefined;
  const contentIv = isV2 && header.contentIv ? header.contentIv : header.iv;

  try {
    // Decrypt metadata (also verifies password).
    let metadata: OQEMetadata;
    try {
      const metadataBytes = await aesDecrypt(encryptedMetadata, contentKey, header.iv, aad);
      metadata = parseMetadata(metadataBytes);
    } catch {
      throw new OQEError('PASSWORD_WRONG', 'Incorrect password or corrupted file');
    }

    // Decrypt file content.
    let plaintext: Uint8Array;
    try {
      plaintext = await aesDecrypt(encryptedContent, contentKey, contentIv, aad);
    } catch {
      throw new OQEError('DECRYPTION_FAILED', 'Failed to decrypt file content');
    }

    return buildResult(plaintext, metadata, 'password');
  } finally {
    contentKey.fill(0);
  }
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

  if (header.algorithmSuite === ALGORITHM_SUITES.HYBRID_X25519_MLKEM1024_AES256GCM) {
    mode = 'hybrid';
    algorithm = 'X25519 + ML-KEM-1024 + AES-256-GCM (AND-combined)';
  } else if (header.algorithmSuite === ALGORITHM_SUITES.HYBRID_X25519_KYBER768_AES256GCM) {
    mode = 'hybrid';
    algorithm = 'X25519 + Kyber + AES-256-GCM (legacy, either-key)';
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
