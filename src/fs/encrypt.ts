/**
 * Omnituum FS - File Encryption
 *
 * Encrypt files using hybrid post-quantum cryptography or password-based encryption.
 * Outputs .oqe (Omnituum Quantum Encrypted) files.
 */

import nacl from 'tweetnacl';
import {
  rand32,
  rand24,
  rand12,
  toHex,
  fromHex,
  hkdfSha256,
  sha256,
  u8,
} from '../crypto/primitives';
import { kyberEncapsulate, isKyberAvailable } from '../crypto/kyber';
import {
  OQE_FORMAT_VERSION,
  ALGORITHM_SUITES,
  OQEMetadata,
  OQEHeader,
  HybridKeyMaterial,
  PasswordKeyMaterial,
  HybridEncryptOptions,
  PasswordEncryptOptions,
  EncryptOptions,
  OQEEncryptResult,
  OQEError,
  FileInput,
  toUint8Array,
  DEFAULT_ARGON2ID_PARAMS,
} from './types';
import { deriveKeyFromPassword, generateArgon2Salt, isArgon2Available } from './argon2';
import { aesEncrypt } from './aes';
import {
  serializeHybridKeyMaterial,
  serializePasswordKeyMaterial,
  serializeMetadata,
  assembleOQEFile,
  addOQEExtension,
} from './format';

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function hkdfFlex(ikm: Uint8Array, salt: string, info: string): Uint8Array {
  return hkdfSha256(ikm, { salt: u8(salt), info: u8(info), length: 32 });
}

function computeIdentityHash(publicKeyHex: string): string {
  const hash = sha256(fromHex(publicKeyHex));
  return toHex(hash).slice(0, 16); // First 8 bytes = 16 hex chars
}

// ═══════════════════════════════════════════════════════════════════════════
// HYBRID MODE ENCRYPTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Encrypt a file using hybrid X25519 + Kyber768 encryption.
 * Provides post-quantum security through dual-algorithm key wrapping.
 */
async function encryptHybrid(
  plaintext: Uint8Array,
  metadata: OQEMetadata,
  options: HybridEncryptOptions
): Promise<OQEEncryptResult> {
  // Verify Kyber is available
  if (!(await isKyberAvailable())) {
    throw new OQEError('KYBER_UNAVAILABLE', 'Kyber library not available in this environment');
  }

  // 1. Generate random content key (32 bytes for AES-256)
  const contentKey = rand32();

  // 2. Generate IV for AES-GCM
  const iv = rand12();

  // 3. Wrap content key with X25519 ECDH
  const x25519EphKp = nacl.box.keyPair();
  const recipientX25519Pk = fromHex(options.recipientPublicKeys.x25519PubHex);
  const x25519Shared = nacl.scalarMult(x25519EphKp.secretKey, recipientX25519Pk);
  const x25519Kek = hkdfFlex(x25519Shared, 'omnituum/fs/x25519', 'wrap-content-key');
  const x25519Nonce = rand24();
  const x25519WrappedKey = nacl.secretbox(contentKey, x25519Nonce, x25519Kek);

  // 4. Wrap content key with Kyber KEM
  const kyberResult = await kyberEncapsulate(options.recipientPublicKeys.kyberPubB64);
  const kyberKek = hkdfFlex(kyberResult.sharedSecret, 'omnituum/fs/kyber', 'wrap-content-key');
  const kyberNonce = rand24();
  const kyberWrappedKey = nacl.secretbox(contentKey, kyberNonce, kyberKek);

  // 5. Serialize key material
  const keyMaterial: HybridKeyMaterial = {
    x25519EphemeralPk: x25519EphKp.publicKey,
    x25519Nonce,
    x25519WrappedKey,
    kyberCiphertext: kyberResult.ciphertext,
    kyberNonce,
    kyberWrappedKey,
  };
  const keyMaterialBytes = serializeHybridKeyMaterial(keyMaterial);

  // 6. Encrypt metadata
  const metadataBytes = serializeMetadata(metadata);
  const { ciphertext: encryptedMetadata } = await aesEncrypt(metadataBytes, contentKey, iv);

  // 7. Encrypt file content
  const { ciphertext: encryptedContent } = await aesEncrypt(plaintext, contentKey, iv);

  // 8. Build header
  const header: OQEHeader = {
    version: OQE_FORMAT_VERSION,
    algorithmSuite: ALGORITHM_SUITES.HYBRID_X25519_KYBER768_AES256GCM,
    flags: 0,
    metadataLength: encryptedMetadata.length,
    keyMaterialLength: keyMaterialBytes.length,
    iv,
  };

  // 9. Assemble complete file
  const fileData = assembleOQEFile({
    header,
    keyMaterial: keyMaterialBytes,
    encryptedMetadata,
    encryptedContent,
  });

  return {
    data: fileData,
    filename: addOQEExtension(metadata.filename),
    metadata,
    mode: 'hybrid',
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// PASSWORD MODE ENCRYPTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Encrypt a file using password-based encryption (Argon2id + AES-256-GCM).
 * Suitable for standalone file protection without identity system.
 */
async function encryptPassword(
  plaintext: Uint8Array,
  metadata: OQEMetadata,
  options: PasswordEncryptOptions
): Promise<OQEEncryptResult> {
  // Verify Argon2 is available
  if (!(await isArgon2Available())) {
    throw new OQEError('ARGON2_UNAVAILABLE', 'Argon2 library not available in this environment');
  }

  // Merge user params with defaults
  const params = {
    ...DEFAULT_ARGON2ID_PARAMS,
    ...options.argon2Params,
  };

  // 1. Generate salt
  const salt = generateArgon2Salt(params.saltLength);

  // 2. Derive content key from password
  const contentKey = await deriveKeyFromPassword(options.password, salt, params);

  // 3. Generate IV for AES-GCM
  const iv = rand12();

  // 4. Serialize key material (Argon2 params + salt)
  const keyMaterial: PasswordKeyMaterial = {
    salt,
    memoryCost: params.memoryCost,
    timeCost: params.timeCost,
    parallelism: params.parallelism,
  };
  const keyMaterialBytes = serializePasswordKeyMaterial(keyMaterial);

  // 5. Encrypt metadata
  const metadataBytes = serializeMetadata(metadata);
  const { ciphertext: encryptedMetadata } = await aesEncrypt(metadataBytes, contentKey, iv);

  // 6. Encrypt file content
  const { ciphertext: encryptedContent } = await aesEncrypt(plaintext, contentKey, iv);

  // 7. Build header
  const header: OQEHeader = {
    version: OQE_FORMAT_VERSION,
    algorithmSuite: ALGORITHM_SUITES.PASSWORD_ARGON2ID_AES256GCM,
    flags: 0,
    metadataLength: encryptedMetadata.length,
    keyMaterialLength: keyMaterialBytes.length,
    iv,
  };

  // 8. Assemble complete file
  const fileData = assembleOQEFile({
    header,
    keyMaterial: keyMaterialBytes,
    encryptedMetadata,
    encryptedContent,
  });

  return {
    data: fileData,
    filename: addOQEExtension(metadata.filename),
    metadata,
    mode: 'password',
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN ENCRYPTION API
// ═══════════════════════════════════════════════════════════════════════════

export interface EncryptFileInput {
  /** File data */
  data: FileInput;
  /** Original filename */
  filename: string;
  /** Optional MIME type */
  mimeType?: string;
}

/**
 * Encrypt a file using hybrid PQC or password-based encryption.
 *
 * @param input - File data and metadata
 * @param options - Encryption options (hybrid or password mode)
 * @returns Encrypted .oqe file result
 *
 * @example
 * // Hybrid mode (with identity)
 * const result = await encryptFile(
 *   { data: fileBytes, filename: 'secret.pdf' },
 *   {
 *     mode: 'hybrid',
 *     recipientPublicKeys: identity.getPublicKeys(),
 *   }
 * );
 *
 * @example
 * // Password mode
 * const result = await encryptFile(
 *   { data: fileBytes, filename: 'secret.pdf' },
 *   {
 *     mode: 'password',
 *     password: 'my-secure-password',
 *   }
 * );
 */
export async function encryptFile(
  input: EncryptFileInput,
  options: EncryptOptions
): Promise<OQEEncryptResult> {
  // Convert input to Uint8Array
  const plaintext = await toUint8Array(input.data);

  // Build metadata
  const metadata: OQEMetadata = {
    filename: input.filename,
    originalSize: plaintext.length,
    mimeType: input.mimeType,
    encryptedAt: new Date().toISOString(),
  };

  // Add identity hashes for hybrid mode
  if (options.mode === 'hybrid') {
    metadata.recipientIdHash = computeIdentityHash(options.recipientPublicKeys.x25519PubHex);
    if (options.sender) {
      metadata.encryptorIdHash = options.sender.id;
    }
  }

  // Encrypt based on mode
  if (options.mode === 'hybrid') {
    return encryptHybrid(plaintext, metadata, options);
  } else {
    return encryptPassword(plaintext, metadata, options);
  }
}

/**
 * Encrypt a file for self (encrypt and decrypt with same identity).
 * Convenience method for personal file encryption.
 */
export async function encryptFileForSelf(
  input: EncryptFileInput,
  identity: {
    id: string;
    name?: string;
    x25519PubHex: string;
    kyberPubB64: string;
  }
): Promise<OQEEncryptResult> {
  return encryptFile(input, {
    mode: 'hybrid',
    recipientPublicKeys: {
      x25519PubHex: identity.x25519PubHex,
      kyberPubB64: identity.kyberPubB64,
    },
    sender: {
      id: identity.id,
      name: identity.name,
    },
  });
}

/**
 * Quick encrypt with password (simple API).
 */
export async function encryptFileWithPassword(
  input: EncryptFileInput,
  password: string
): Promise<OQEEncryptResult> {
  return encryptFile(input, {
    mode: 'password',
    password,
  });
}
