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
  b64,
  hkdfSha256,
  sha256,
  u8,
} from '../crypto/primitives';
import { kyberEncapsulate, isKyberAvailable } from '../crypto/kyber';
import {
  OQE_FORMAT_VERSION_V2,
  ALGORITHM_SUITES,
  OQEMetadata,
  OQEHeader,
  HybridKeyMaterialV2,
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
import { aesEncrypt, AES_GCM_TAG_SIZE } from './aes';
import {
  serializeHybridKeyMaterialV2,
  serializePasswordKeyMaterial,
  serializeMetadata,
  writeOQEHeader,
  assembleOQEFile,
  addOQEExtension,
} from './format';

// AES-GCM tag length is fixed at 16 bytes, so GCM ciphertext length is known
// before encryption. This lets us build (and thus AAD-bind) the full header,
// including metadataLength, prior to the actual encrypt calls.
const AES_GCM_TAG_LEN = AES_GCM_TAG_SIZE;

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function computeIdentityHash(publicKeyHex: string): string {
  const hash = sha256(fromHex(publicKeyHex));
  return toHex(hash).slice(0, 16); // First 8 bytes = 16 hex chars
}

/**
 * Derive the v2 AND-combined KEK for file encryption. Requires BOTH shared
 * secrets; the envelope's own KEM values are bound into the HKDF info so a
 * spliced ephemeral key or Kyber ciphertext derives a different KEK and the
 * wrap fails authentication (X-Wing-style transcript binding). Domain-separated
 * from the message-envelope KEK via the "omnituum/fs/hybrid-v2" salt.
 */
export function combinedFileKekV2(
  kyberShared: Uint8Array,
  x25519Shared: Uint8Array,
  x25519EpkHex: string,
  kyberKemCtB64: string
): Uint8Array {
  const ikm = new Uint8Array(kyberShared.length + x25519Shared.length);
  ikm.set(kyberShared, 0);
  ikm.set(x25519Shared, kyberShared.length);
  try {
    return hkdfSha256(ikm, {
      salt: u8('omnituum/fs/hybrid-v2'),
      info: u8(`wrap-content-key|${x25519EpkHex}|${kyberKemCtB64}`),
      length: 32,
    });
  } finally {
    ikm.fill(0);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// HYBRID MODE ENCRYPTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Encrypt a file using hybrid X25519 + ML-KEM-1024 encryption (OQE v2).
 *
 * The content key is wrapped exactly once, under a KEK derived from BOTH shared
 * secrets together (AND-combined) — breaking either primitive alone is
 * insufficient to unwrap. Metadata and content are encrypted under separate
 * AES-GCM IVs, and the full serialized header (version, suite, flags, lengths,
 * both IVs) is bound as AEAD associated data.
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

  try {
    // 2. Separate IVs for metadata and content — never reuse a (key, nonce) pair.
    const metadataIv = rand12();
    const contentIv = rand12();

    // 3. X25519 ECDH shared secret (ephemeral)
    const x25519EphKp = nacl.box.keyPair();
    const recipientX25519Pk = fromHex(options.recipientPublicKeys.x25519PubHex);
    const x25519Shared = nacl.scalarMult(x25519EphKp.secretKey, recipientX25519Pk);
    const x25519EpkHex = toHex(x25519EphKp.publicKey);

    // 4. ML-KEM-1024 shared secret
    const kyberResult = await kyberEncapsulate(options.recipientPublicKeys.kyberPubB64);
    const kyberKemCtB64 = b64(kyberResult.ciphertext);

    // 5. Single wrap under the AND-combined, transcript-bound KEK.
    const kek = combinedFileKekV2(kyberResult.sharedSecret, x25519Shared, x25519EpkHex, kyberKemCtB64);
    const ckWrapNonce = rand24();
    const ckWrapped = nacl.secretbox(contentKey, ckWrapNonce, kek);
    kek.fill(0);
    x25519Shared.fill(0);
    kyberResult.sharedSecret.fill(0);
    x25519EphKp.secretKey.fill(0);

    // 6. Serialize key material
    const keyMaterial: HybridKeyMaterialV2 = {
      x25519EphemeralPk: x25519EphKp.publicKey,
      kyberCiphertext: kyberResult.ciphertext,
      ckWrapNonce,
      ckWrapped,
    };
    const keyMaterialBytes = serializeHybridKeyMaterialV2(keyMaterial);

    // 7. Build header up-front so it can be used as AAD. GCM ciphertext length
    //    is plaintext length + tag, so metadataLength is known before encrypting.
    const metadataBytes = serializeMetadata(metadata);
    const header: OQEHeader = {
      version: OQE_FORMAT_VERSION_V2,
      algorithmSuite: ALGORITHM_SUITES.HYBRID_X25519_MLKEM1024_AES256GCM,
      flags: 0,
      metadataLength: metadataBytes.length + AES_GCM_TAG_LEN,
      keyMaterialLength: keyMaterialBytes.length,
      iv: metadataIv,
      contentIv,
    };
    const aad = writeOQEHeader(header);

    // 8. Encrypt metadata and content under distinct IVs, header bound as AAD.
    const { ciphertext: encryptedMetadata } = await aesEncrypt(metadataBytes, contentKey, metadataIv, aad);
    const { ciphertext: encryptedContent } = await aesEncrypt(plaintext, contentKey, contentIv, aad);

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
  } finally {
    contentKey.fill(0);
  }
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

  try {
    // 3. Separate IVs for metadata and content — never reuse a (key, nonce) pair.
    const metadataIv = rand12();
    const contentIv = rand12();

    // 4. Serialize key material (Argon2 params + salt)
    const keyMaterial: PasswordKeyMaterial = {
      salt,
      memoryCost: params.memoryCost,
      timeCost: params.timeCost,
      parallelism: params.parallelism,
    };
    const keyMaterialBytes = serializePasswordKeyMaterial(keyMaterial);

    // 5. Build header up-front for AAD binding.
    const metadataBytes = serializeMetadata(metadata);
    const header: OQEHeader = {
      version: OQE_FORMAT_VERSION_V2,
      algorithmSuite: ALGORITHM_SUITES.PASSWORD_ARGON2ID_AES256GCM,
      flags: 0,
      metadataLength: metadataBytes.length + AES_GCM_TAG_LEN,
      keyMaterialLength: keyMaterialBytes.length,
      iv: metadataIv,
      contentIv,
    };
    const aad = writeOQEHeader(header);

    // 6. Encrypt metadata and content under distinct IVs, header bound as AAD.
    const { ciphertext: encryptedMetadata } = await aesEncrypt(metadataBytes, contentKey, metadataIv, aad);
    const { ciphertext: encryptedContent } = await aesEncrypt(plaintext, contentKey, contentIv, aad);

    // 7. Assemble complete file
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
  } finally {
    contentKey.fill(0);
  }
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
